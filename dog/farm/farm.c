/*
 * Copyright (C) 2011 Taobao Inc.
 * Copyright (C) 2013 Zelin.io
 *
 * Liu Yuan <namei.unix@gmail.com>
 * Kai Zhang <kyle@zelin.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <pthread.h>

#include "farm.h"
#include "rbtree.h"

static char farm_object_dir[PATH_MAX];
static char farm_dir[PATH_MAX];

static struct sd_rw_lock active_vdi_lock = SD_RW_LOCK_INITIALIZER;

struct load_vdi_entry {
	struct rb_node rb;
	uint32_t vid;
	uint32_t parent_vid;
	uint8_t nr_copies;
	uint8_t copy_policy;
	uint8_t block_size_shift;
	/* the snapshot carries an inode object for this vid */
	bool has_inode;
	bool notified;
};

struct active_vdi_entry {
	struct rb_node rb;
	char name[SD_MAX_VDI_LEN];
	uint64_t vdi_size;
	uint32_t vdi_id;
	uint32_t snap_id;
	uint32_t acl_id;
	uint8_t  nr_copies;
	uint8_t copy_policy;
	uint8_t store_policy;
	uint8_t block_size_shift;
};

struct registered_obj_entry {
	struct rb_node rb;
	uint64_t oid;
};

/* We use active_vdi_tree to create active vdi on top of the snapshot chain */
static struct rb_root active_vdi_tree = RB_ROOT;
/* We have to register vdi information first before loading objects */
static struct rb_root load_vdi_tree = RB_ROOT;
/* register object iff vdi specified */
static struct rb_root registered_obj_tree = RB_ROOT;
static uint64_t obj_to_load;

struct snapshot_work {
	struct trunk_entry entry;
	struct strbuf *trunk_buf;
	struct work work;
};
static struct work_queue *wq;
static uatomic_bool work_error;

static int vdi_cmp(const struct active_vdi_entry *e1,
		   const struct active_vdi_entry *e2)
{
	return strcmp(e1->name, e2->name);
}

static void update_active_vdi_entry(struct active_vdi_entry *vdi,
				    struct sd_inode_header *new)
{
	pstrcpy(vdi->name, sizeof(vdi->name), new->name);
	vdi->vdi_size = new->vdi_size;
	vdi->vdi_id = new->vdi_id;
	vdi->snap_id = new->snap_id;
	vdi->acl_id = new->acl_id;
	vdi->nr_copies = new->nr_copies;
	vdi->copy_policy = new->copy_policy;
	vdi->store_policy = new->store_policy;
	vdi->block_size_shift = new->block_size_shift;
}

static void add_active_vdi(struct sd_inode_header *new)
{
	struct active_vdi_entry *vdi, *ret;

	vdi = xmalloc(sizeof(struct active_vdi_entry));

	update_active_vdi_entry(vdi, new);
	sd_write_lock(&active_vdi_lock);
	ret = rb_insert(&active_vdi_tree, vdi, rb, vdi_cmp);
	if (ret && ret->snap_id < new->snap_id) {
		update_active_vdi_entry(ret, new);
		free(vdi);
	}
	sd_rw_unlock(&active_vdi_lock);
}

static int load_vdi_cmp(struct load_vdi_entry *a, struct load_vdi_entry *b)
{
	return intcmp(a->vid, b->vid);
}

/*
 * load_vdi_tree is built and walked before the load work queue is started, so
 * it needs no locking.
 */
static struct load_vdi_entry *lookup_load_vdi(uint32_t vid)
{
	struct load_vdi_entry key = { .vid = vid };

	return rb_search(&load_vdi_tree, &key, rb, load_vdi_cmp);
}

static struct load_vdi_entry *register_load_vdi(uint32_t vid)
{
	struct load_vdi_entry *new = xzalloc(sizeof(*new)), *ret;

	new->vid = vid;

	ret = rb_insert(&load_vdi_tree, new, rb, load_vdi_cmp);
	if (ret) {
		free(new);
		return ret;
	}

	return new;
}

static int create_active_vdis(void)
{
	struct active_vdi_entry *vdi;
	uint32_t new_vid;
	rb_for_each_entry(vdi, &active_vdi_tree, rb) {
		if (do_vdi_create(vdi->name, vdi->vdi_size,
				  vdi->vdi_id, vdi->acl_id, &new_vid,
				  false, vdi->nr_copies,
				  vdi->copy_policy,
				  vdi->store_policy,
				  vdi->block_size_shift) < 0)
			return -1;
	}
	return 0;
}

char *get_object_directory(void)
{
	return farm_object_dir;
}

static int create_directory(const char *p)
{
	int ret = -1;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, p);
	if (xmkdir(buf.buf, 0755) < 0) {
		if (errno == EEXIST)
			sd_err("Path is not a directory: %s", p);
		goto out;
	}

	if (!strlen(farm_dir))
		strbuf_copyout(&buf, farm_dir, sizeof(farm_dir));

	strbuf_addstr(&buf, "/objects");
	if (xmkdir(buf.buf, 0755) < 0)
		goto out;

	for (int i = 0; i < 256; i++) {
		strbuf_addf(&buf, "/%02x", i);
		if (xmkdir(buf.buf, 0755) < 0)
			goto out;

		strbuf_remove(&buf, buf.len - 3, 3);
	}

	if (!strlen(farm_object_dir))
		strbuf_copyout(&buf, farm_object_dir, sizeof(farm_object_dir));

	ret = 0;
out:
	if (ret)
		sd_err("Fail to create directory: %m");
	strbuf_release(&buf);
	return ret;
}

static int get_trunk_sha1(uint32_t idx, const char *tag, unsigned char *outsha1)
{
	int nr_logs = -1, ret = -1;
	struct snap_log *log_buf, *log_free = NULL;

	log_free = log_buf = snap_log_read(&nr_logs);
	if (IS_ERR(log_free))
		goto out;

	for (int i = 0; i < nr_logs; i++, log_buf++) {
		if (log_buf->idx != idx && strcmp(log_buf->tag, tag))
			continue;
		memcpy(outsha1, log_buf->trunk_sha1, SHA1_DIGEST_SIZE);
		ret = 0;
		goto out;
	}
out:
	free(log_free);
	return ret;
}

static int notify_vdi_add(uint32_t vdi_id, uint8_t nr_copies,
			  uint8_t copy_policy, uint8_t block_size_shift,
			  uint32_t old_vid, bool deleted)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char *buf = NULL;

	sd_init_req(&hdr, SD_OP_NOTIFY_VDI_ADD);
	hdr.vdi_state.old_vid = old_vid;
	hdr.vdi_state.new_vid = vdi_id;
	hdr.vdi_state.copies = nr_copies;
	hdr.vdi_state.copy_policy = copy_policy;
	hdr.vdi_state.block_size_shift = block_size_shift;
	hdr.vdi_state.set_bitmap = true;
	hdr.vdi_state.set_deleted = deleted;

	ret = dog_exec_req(&sd_nid, &hdr, buf);

	if (ret < 0)
		sd_err("Fail to notify vdi add event(%"PRIx32", %d"
		       ", %"PRIu8")", vdi_id, nr_copies, block_size_shift);
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("%s", sd_strerror(rsp->result));
		ret = -1;
	}

	free(buf);
	return ret;
}

int farm_init(const char *path)
{
	int ret = -1;

	if (create_directory(path) < 0)
		goto out;
	if (snap_init(farm_dir) < 0)
		goto out;
	return 0;
out:
	if (ret)
		sd_err("Fail to init farm.");
	return ret;
}

bool farm_contain_snapshot(uint32_t idx, const char *tag)
{
	unsigned char trunk_sha1[SHA1_DIGEST_SIZE];
	return (get_trunk_sha1(idx, tag, trunk_sha1) == 0);
}

static void do_save_object(struct work *work)
{
	void *buf;
	size_t size;
	struct snapshot_work *sw;

	if (uatomic_is_true(&work_error))
		return;

	sw = container_of(work, struct snapshot_work, work);

	size = get_objsize(sw->entry.oid,
			  (UINT32_C(1) <<  sw->entry.block_size_shift));
	buf = xmalloc(size);

	if (dog_read_object(sw->entry.oid, buf, size, 0, true) < 0)
		goto error;

	if (slice_write(buf, size, sw->entry.sha1) < 0)
		goto error;

	free(buf);
	return;
error:
	free(buf);
	sd_err("Fail to save object, oid %016"PRIx64, sw->entry.oid);
	uatomic_set_true(&work_error);
}

static void farm_show_progress(uint64_t done, uint64_t total)
{
	return show_progress(done, total, true);
}

static void save_object_done(struct work *work)
{
	struct snapshot_work *sw = container_of(work, struct snapshot_work,
						work);
	static unsigned long saved;

	if (uatomic_is_true(&work_error))
		goto out;

	strbuf_add(sw->trunk_buf, &sw->entry, sizeof(struct trunk_entry));
	farm_show_progress(uatomic_add_return(&saved, 1), object_tree_size());
out:
	free(sw);
}

static int queue_save_snapshot_work(uint64_t oid, uint32_t nr_copies,
				    uint8_t copy_policy,
				    uint8_t block_size_shift, void *data)
{
	struct snapshot_work *sw = xzalloc(sizeof(struct snapshot_work));
	struct strbuf *trunk_buf = data;

	sw->entry.oid = oid;
	sw->entry.nr_copies = nr_copies;
	sw->entry.copy_policy = copy_policy;
	sw->entry.block_size_shift = block_size_shift;
	sw->trunk_buf = trunk_buf;
	sw->work.fn = do_save_object;
	sw->work.done = save_object_done;
	queue_work(wq, &sw->work);

	return 0;
}

int farm_save_snapshot(const char *tag, bool multithread)
{
	unsigned char trunk_sha1[SHA1_DIGEST_SIZE];
	struct strbuf trunk_buf;
	void *snap_log = NULL;
	int log_nr, idx, ret;
	uint64_t nr_objects = object_tree_size();

	snap_log = snap_log_read(&log_nr);
	if (IS_ERR(snap_log)) {
		ret = -1;
		goto out;
	}

	idx = log_nr + 1;
	if (!log_nr) {
		struct sd_req hdr;
		struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
		struct snap_log_hdr log_hdr;

		sd_init_req(&hdr, SD_OP_CLUSTER_STATUS);
		ret = dog_exec_req(&sd_nid, &hdr, NULL);
		if (ret < 0) {
			sd_err("Fail to execute request");
			goto out;
		}
		if (rsp->result != SD_RES_SUCCESS) {
			sd_err("%s", sd_strerror(rsp->result));
			ret = -1;
			goto out;
		}
		log_hdr.magic = FARM_MAGIC;
		log_hdr.version = FARM_VERSION;
		log_hdr.copy_number = rsp->cluster.nr_copies;
		log_hdr.copy_policy = rsp->cluster.copy_policy;
		log_hdr.block_size_shift = rsp->cluster.block_size_shift;
		snap_log_write_hdr(&log_hdr);
	}

	strbuf_init(&trunk_buf, sizeof(struct trunk_entry) * nr_objects);

	wq = create_work_queue("save snapshot",
			       multithread ? WQ_DYNAMIC : WQ_ORDERED);
	if (for_each_object_in_tree(queue_save_snapshot_work,
				    &trunk_buf) < 0) {
		ret = -1;
		goto out;
	}

	work_queue_wait(wq);
	if (uatomic_is_true(&work_error)) {
		ret = -1;
		goto out;
	}

	if (trunk_file_write(nr_objects, (struct trunk_entry *)trunk_buf.buf,
			     trunk_sha1) < 0) {
		ret = -1;
		goto out;
	}

	if (snap_log_append(idx, tag, trunk_sha1) < 0) {
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	strbuf_release(&trunk_buf);
	free(snap_log);
	return ret;
}

static void do_load_object(struct work *work)
{
	void *buffer = NULL;
	size_t size;
	struct snapshot_work *sw;
	static unsigned long loaded;

	if (uatomic_is_true(&work_error))
		return;

	sw = container_of(work, struct snapshot_work, work);

	buffer = slice_read(sw->entry.sha1, &size);

	if (!buffer)
		goto error;

	/* the vids of all objects have been reserved by reserve_load_vdis() */
	if (dog_write_object(sw->entry.oid, 0, buffer, size, 0,
			     SD_FLAG_CMD_DIRECT, sw->entry.nr_copies,
			     sw->entry.copy_policy, true) != 0)
		goto error;

	if (is_vdi_obj(sw->entry.oid))
		add_active_vdi(buffer);

	farm_show_progress(uatomic_add_return(&loaded, 1),
			(obj_to_load > 0) ? obj_to_load : trunk_get_count());
	free(buffer);
	return;
error:
	free(buffer);
	sd_err("Fail to load object, oid %016"PRIx64, sw->entry.oid);
	uatomic_set_true(&work_error);
}

static void load_object_done(struct work *work)
{
	struct snapshot_work *sw = container_of(work, struct snapshot_work,
						work);

	free(sw);
}

static int registered_obj_cmp(struct registered_obj_entry *a,
			      struct registered_obj_entry *b)
{
	return intcmp(a->oid, b->oid);
}

/* Is this trunk entry part of the set of objects we are going to load? */
static bool entry_to_load(struct trunk_entry *entry)
{
	struct registered_obj_entry key;

	if (obj_to_load == 0)
		return true;

	key.oid = entry->oid;
	return rb_search(&registered_obj_tree, &key, rb,
			 registered_obj_cmp) != NULL;
}

/*
 * Collect the vid of every object we are going to load, together with the
 * parent vid of the ones which come with an inode object.
 */
static int collect_load_vdi_entry(struct trunk_entry *entry, void *data)
{
	struct load_vdi_entry *lv;
	struct sd_inode_header *header;
	size_t size;

	if (!entry_to_load(entry))
		return 0;

	lv = register_load_vdi(oid_to_vid(entry->oid));

	if (!is_vdi_obj(entry->oid)) {
		/*
		 * Data objects are shared with the descendants of their owner,
		 * so this vid might not have an inode object of its own.  Do
		 * not overwrite the values taken from an inode object.
		 */
		if (!lv->has_inode) {
			lv->nr_copies = entry->nr_copies;
			lv->copy_policy = entry->copy_policy;
			lv->block_size_shift = entry->block_size_shift;
		}
		return 0;
	}

	header = slice_read(entry->sha1, &size);
	if (!header) {
		sd_err("Fail to load vdi object, oid %016"PRIx64, entry->oid);
		return -1;
	}

	lv->has_inode = true;
	lv->nr_copies = entry->nr_copies;
	lv->copy_policy = entry->copy_policy;
	lv->block_size_shift = entry->block_size_shift;
	if (size < sizeof(*header))
		sd_warn("only %zu of %zu bytes of inode header, cannot tell"
			" the parent of oid %016"PRIx64, size, sizeof(*header),
			entry->oid);
	else
		lv->parent_vid = header->parent_vdi_id;
	free(header);

	return 0;
}

/*
 * Make the cluster aware of every vid we are about to load, without saying
 * anything about the snapshot chain yet: a vid which is known to be a snapshot
 * has read-only data objects, so linking the family here would make the load
 * of those very objects fail.  That is left to link_load_vdis().
 */
static int reserve_load_vdis(void)
{
	struct load_vdi_entry *lv;

	rb_for_each_entry(lv, &load_vdi_tree, rb) {
		/*
		 * A vid without an inode object of its own is a snapshot which
		 * got deleted while its data objects were still shared by a
		 * descendant.  Reserve the vid so that a later vdi creation
		 * cannot reuse it and clobber those data objects, and mark it
		 * deleted so that it is skipped when walking the in-use
		 * bitmap.
		 */
		if (notify_vdi_add(lv->vid, lv->nr_copies, lv->copy_policy,
				   lv->block_size_shift, 0,
				   !lv->has_inode) < 0)
			return -1;
	}

	return 0;
}

/*
 * Tell the cluster about the parent of a vid so that the sheeps can rebuild
 * the VDI family and recycle the whole of it once all its members are deleted.
 *
 * Ancestors go first: a vid is passed as the old vid of its child, which turns
 * it into a snapshot, and as the new vid of its own notification, which turns
 * it back into a working VDI.  Parents first leaves every vid with a child a
 * snapshot and the tip of each chain a working VDI.
 */
static int link_load_vdi(struct load_vdi_entry *lv)
{
	struct load_vdi_entry *parent;

	if (lv->notified)
		return 0;
	lv->notified = true;

	/*
	 * Only pass on a parent which is part of this snapshot, registering a
	 * vid we don't restore would add a family member which never gets
	 * deleted and thus pins the whole family.
	 */
	parent = lv->parent_vid ? lookup_load_vdi(lv->parent_vid) : NULL;
	if (!parent)
		return 0;

	if (link_load_vdi(parent) < 0)
		return -1;

	return notify_vdi_add(lv->vid, lv->nr_copies, lv->copy_policy,
			      lv->block_size_shift, parent->vid,
			      !lv->has_inode);
}

static int link_load_vdis(void)
{
	struct load_vdi_entry *lv;

	rb_for_each_entry(lv, &load_vdi_tree, rb) {
		if (link_load_vdi(lv) < 0)
			return -1;
	}

	return 0;
}

static int queue_load_snapshot_work(struct trunk_entry *entry, void *data)
{
	struct snapshot_work *sw;

	if (!entry_to_load(entry))
		return 0;

	sw = xzalloc(sizeof(struct snapshot_work));

	memcpy(&sw->entry, entry, sizeof(struct trunk_entry));
	sw->work.fn = do_load_object;
	sw->work.done = load_object_done;
	queue_work(wq, &sw->work);

	return 0;
}

static int visit_vdi_obj_entry(struct trunk_entry *entry, void *data)
{
	size_t size;
	void *slice;
	struct sd_inode *inode;
	struct vdi_option *opt = (struct vdi_option *)data;

	if (!is_vdi_obj(entry->oid))
		return 0;

	slice = slice_read(entry->sha1, &size);
	if (!slice) {
		sd_err("Fail to load vdi object, oid %016"PRIx64, entry->oid);
		return -1;
	}
	inode = xmalloc(sizeof(*inode));
	if (size > sizeof(*inode)) {
		sd_err("trying to load %lu of %lu bytes of inode data",
		       size, sizeof(*inode));
		size = sizeof(*inode);
	} else if (size < sizeof(*inode)) {
		sd_warn("only load %lu of %lu bytes of inode data",
			size, sizeof(*inode));
	}
	memcpy(inode, slice, size);
	free(slice);
	if (opt->count == 0) {
		if (opt->enable_if_blank)
			opt->func(inode);
	} else if (inode->header.name[0] == '\0') {
		if (opt->enable_if_deleted)
			opt->func(inode);
	} else {
		for (int i = 0; i < opt->count; i++)
			if (!strcmp(inode->header.name, opt->name[i])) {
				opt->func(inode);
				break;
			}
	}
	free(inode);
	return 0;
}

static void do_register_obj(uint64_t oid)
{
	struct registered_obj_entry *new;

	new = xmalloc(sizeof(*new));
	new->oid = oid;
	if (rb_search(&registered_obj_tree, new, rb, registered_obj_cmp)) {
		free(new);
		return;
	}

	rb_insert(&registered_obj_tree, new, rb, registered_obj_cmp);
	obj_to_load++;
}

static void register_obj(struct sd_inode *inode)
{
	do_register_obj(vid_to_vdi_oid(inode->header.vdi_id));

	for (int i = 0; i < SD_INODE_DATA_INDEX; i++) {
		if (!inode->data_vdi_id[i])
			continue;

		do_register_obj(vid_to_data_oid(inode->data_vdi_id[i], i));
	}
}

int farm_load_snapshot(uint32_t idx, const char *tag, int count, char **name)
{
	int ret = -1;
	unsigned char trunk_sha1[SHA1_DIGEST_SIZE];
	struct vdi_option opt;

	memset(trunk_sha1, 0, sizeof(trunk_sha1));
	if (get_trunk_sha1(idx, tag, trunk_sha1) < 0)
		goto out;

	opt.count = count;
	opt.name = name;
	opt.func = register_obj;
	opt.enable_if_blank = false;
	opt.enable_if_deleted = true;

	if (for_each_entry_in_trunk(trunk_sha1, visit_vdi_obj_entry, &opt) < 0)
		goto out;

	if (count > 0 && obj_to_load == 0) {
		sd_err("Objects of specified VDIs are not found "
			   "in local cluster snapshot storage.");
		goto out;
	}

	/*
	 * Reserve all vids before starting the workers, the objects themselves
	 * are loaded in arbitrary order.
	 */
	if (for_each_entry_in_trunk(trunk_sha1, collect_load_vdi_entry,
				    NULL) < 0)
		goto out;

	if (reserve_load_vdis() < 0)
		goto out;

	wq = create_work_queue("load snapshot", WQ_DYNAMIC);
	if (for_each_entry_in_trunk(trunk_sha1, queue_load_snapshot_work,
				    NULL) < 0)
		goto out;

	work_queue_wait(wq);
	if (uatomic_is_true(&work_error))
		goto out;

	/* all objects are in place, the snapshot chain can be rebuilt now */
	if (link_load_vdis() < 0)
		goto out;

	if (create_active_vdis() < 0)
		goto out;

	ret = 0;
out:
	rb_destroy(&active_vdi_tree, struct active_vdi_entry, rb);
	rb_destroy(&load_vdi_tree, struct load_vdi_entry, rb);
	rb_destroy(&registered_obj_tree, struct registered_obj_entry, rb);
	return ret;
}

static void print_vdi(struct sd_inode *inode)
{
	static int seq;

	sd_info("%d. VDI id: %"PRIx32", name: %s, tag: %s",
		++seq, inode->header.vdi_id,
		inode->header.name, inode->header.tag);
}

int farm_show_snapshot(uint32_t idx, const char *tag, int count, char **name)
{
	int ret = -1;
	unsigned char trunk_sha1[SHA1_DIGEST_SIZE];
	struct vdi_option opt;

	if (get_trunk_sha1(idx, tag, trunk_sha1) < 0)
		goto out;

	opt.count = count;
	opt.name = name;
	opt.func = print_vdi;
	opt.enable_if_blank = true;
	opt.enable_if_deleted = false;

	if (for_each_entry_in_trunk(trunk_sha1, visit_vdi_obj_entry, &opt) < 0)
		goto out;

	ret = 0;
out:
	if (ret)
		sd_err("Fail to show snapshot.");
	return ret;
}
