/*
 * Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <libgen.h>

#include "sheep_priv.h"

struct store_cache_entry {
	uint64_t oid;
	struct rb_node node;
	char *path;
	int fd;
};

static struct rb_root store_cache_root = RB_ROOT;
static struct sd_mutex store_cache_lock = SD_MUTEX_INITIALIZER;

static int store_cache_cmp(const struct store_cache_entry *a,
			   const struct store_cache_entry *b)
{
	return intcmp(a->oid, b->oid);
}

static struct store_cache_entry *store_cache_lookup_by_oid(uint64_t oid)
{
	struct store_cache_entry *entry, key = { .oid = oid };

	sd_mutex_lock(&store_cache_lock);
	entry = rb_search(&store_cache_root, &key, node, store_cache_cmp);
	sd_mutex_unlock(&store_cache_lock);
	return entry;
}

static struct store_cache_entry *store_cache_lookup(uint64_t oid)
{
	struct store_cache_entry *entry, *new = xzalloc(sizeof(*new));

	if (!new)
		return NULL;
	sd_mutex_lock(&store_cache_lock);
	new->oid = oid;
	new->fd = -1;
	entry = rb_insert(&store_cache_root, new, node, store_cache_cmp);
	if (entry) {
		sys->cache_stat.nr_cache_entries++;
		free(new);
	} else {
		sys->cache_stat.nr_cache_hits++;
		entry = new;
	}
	sd_mutex_unlock(&store_cache_lock);
	return entry;
}

static void store_cache_remove(struct store_cache_entry *entry)
{
	sd_mutex_lock(&store_cache_lock);
	rb_erase(&entry->node, &store_cache_root);
	sys->cache_stat.nr_cache_entries--;
	sd_mutex_unlock(&store_cache_lock);
	if (entry->fd != -1) {
		close(entry->fd);
		sys->cache_stat.nr_close++;
	}
	if (entry->path)
		free(entry->path);
	free(entry);
}

static struct store_cache_entry *store_cache_remove_by_oid(uint64_t oid)
{
	struct store_cache_entry *entry, key = { .oid = oid };

	sd_mutex_lock(&store_cache_lock);
	entry = rb_search(&store_cache_root, &key, node, store_cache_cmp);
	if (entry) {
		rb_erase(&entry->node, &store_cache_root);
		sys->cache_stat.nr_cache_entries--;
	}
	sd_mutex_unlock(&store_cache_lock);
	return entry;
}

static int get_store_path(uint64_t oid, uint8_t ec_index, char **path)
{
	int ret;

	if (is_erasure_oid(oid)) {
		if (unlikely(ec_index >= SD_MAX_COPIES)) {
			panic("invalid ec_index %d", ec_index);
			errno = EINVAL;
			return -1;
		}
		ret = asprintf(path, "%s/%016"PRIx64"_%d",
			       md_get_object_dir(oid), oid, ec_index);
	} else
		ret = asprintf(path, "%s/%016" PRIx64,
			       md_get_object_dir(oid), oid);
	return ret < 0 ? ret : 0;
}

/*
 * Every writer gets a temporary file of its own.
 *
 * Two writers can legitimately create the same object at the same time; a
 * retried gateway CREATE racing the recovery of that very object, say, or two
 * recovery workers which were handed the same oid.  They write identical data,
 * so whoever renames last wins and the object becomes visible as soon as the
 * first of them is done.  Sharing a single temporary name instead means the
 * second writer finds the file already there and has no way to tell whether
 * the other one has reached its rename() yet.
 */
static int get_store_tmp_path(uint64_t oid, uint8_t ec_index, char **path)
{
	char *tmp_path;
	int ret;

	ret = get_store_path(oid, ec_index, &tmp_path);
	if (ret < 0)
		return ret;

	ret = asprintf(path, "%s.tmp.%d", tmp_path, gettid());
	free(tmp_path);
	return ret < 0 ? ret : 0;
}

static int get_store_stale_path(uint64_t oid, uint32_t epoch, uint8_t ec_index,
				char **path)
{
	return md_get_stale_path(oid, epoch, ec_index, path);
}

/*
 * Check if oid is in this nodes (if oid is in the wrong place, it will be moved
 * to the correct one after this call in a MD setup.
 */
bool default_exist(uint64_t oid, uint8_t ec_index)
{
	struct store_cache_entry *entry;
	char *path;
	int ret;

	entry = store_cache_lookup_by_oid(oid);
	if (entry && entry->fd >= 0) {
		struct stat st;

		if (fstat(entry->fd, &st) < 0 || st.st_nlink == 0) {
			store_cache_remove(entry);
			return false;
		} else
			return true;
	}
	ret = get_store_path(oid, ec_index, &path);
	if (ret < 0)
		return false;

	if (md_exist(oid, ec_index, path)) {
		free(path);
		return true;
	}
	free(path);
	return false;
}

/* Trim zero blocks of the beginning and end of the object. */
static int default_trim(int fd, uint64_t oid, const struct siocb *iocb,
			uint64_t *poffset, uint32_t *plen)
{
	trim_zero_blocks(iocb->buf, poffset, plen);

	if (iocb->offset < *poffset) {
		sd_debug("discard between %d, %ld, %016" PRIx64, iocb->offset,
			 *poffset, oid);

		if (discard(fd, iocb->offset, *poffset) < 0)
			return -1;
	}

	if (*poffset + *plen < iocb->offset + iocb->length) {
		uint64_t end = iocb->offset + iocb->length;
		uint32_t object_size = get_vdi_object_size(oid_to_vid(oid));
		if (end == get_objsize(oid, object_size))
			/* This is necessary to punch the last block */
			end = round_up(end, getpagesize());
		sd_debug("discard between %ld, %ld, %016" PRIx64, *poffset + *plen,
			 end, oid);

		if (discard(fd, *poffset + *plen, end) < 0)
			return -1;
	}

	return 0;
}

int default_write(uint64_t oid, const struct siocb *iocb)
{
	int flags = prepare_iocb(oid, iocb, false),
		ret = SD_RES_SUCCESS;
	ssize_t size;
	uint32_t len = iocb->length;
	uint64_t offset = iocb->offset;
	static bool trim_is_supported = true;
	struct store_cache_entry *entry;

	if (iocb->epoch < sys_epoch()) {
		sd_debug("%"PRIu32" sys q%"PRIu32, iocb->epoch, sys_epoch());
		return SD_RES_OLD_NODE_VER;
	}

	if (uatomic_is_true(&sys->use_journal) &&
	    unlikely(journal_write_store(oid, iocb->buf, iocb->length,
					 iocb->offset, false))
	    != SD_RES_SUCCESS) {
		sd_err("turn off journaling");
		uatomic_set_false(&sys->use_journal);
		flags |= O_DSYNC;
		sync();
	}

	entry = store_cache_lookup(oid);
	if (!entry)
		return SD_RES_NO_MEM;

	if (entry->fd >= 0) {
		struct stat st;

		/*
		 * A cached fd can outlive the file it points at (e.g. the
		 * object's disk got pulled out from under us): xpwrite()
		 * on such a fd silently succeeds against the orphaned
		 * inode instead of failing, so disk failures would go
		 * undetected. Catch it via nlink before trusting the cache.
		 */
		if (fstat(entry->fd, &st) < 0 || st.st_nlink == 0) {
			ret = err_to_sderr(entry->path, entry->oid, ENOENT);
			goto out_remove;
		}
		goto do_write;
	}

	if (!entry->path) {
		ret = get_store_path(entry->oid, iocb->ec_index, &entry->path);
		if (ret < 0) {
			entry->path = NULL;
			ret = SD_RES_NO_MEM;
			goto out_remove;
		}
	}

	/*
	 * Make sure oid is in the right place because oid might be misplaced
	 * in a wrong place, due to 'shutdown/restart with less/more disks' or
	 * any bugs. We need call err_to_sderr() to return EIO if disk is broken
	 */
	if (!md_exist(entry->oid, iocb->ec_index, entry->path)) {
		ret = err_to_sderr(entry->path, entry->oid, ENOENT);
		goto out_remove;
	}

	entry->fd = open(entry->path, flags, sd_def_fmode);
	if (unlikely(entry->fd < 0)) {
		ret = err_to_sderr(entry->path, entry->oid, errno);
		goto out_remove;
	}
	sys->cache_stat.nr_open++;
do_write:
	if (trim_is_supported && is_sparse_object(oid)) {
		if (default_trim(entry->fd, oid, iocb, &offset, &len) < 0) {
			trim_is_supported = false;
			offset = iocb->offset;
			len = iocb->length;
		}
	}

	size = xpwrite(entry->fd, iocb->buf, len, offset);
	if (unlikely(size != len)) {
		sd_err("failed to write object %016"PRIx64", path=%s, offset=%"
		       PRId32", size=%"PRId32", result=%zd, %m", oid,
		       entry->path, iocb->offset, iocb->length, size);
		ret = err_to_sderr(entry->path, oid, errno);
	}
out_remove:
	if (ret != SD_RES_SUCCESS)
		store_cache_remove(entry);

	return ret;
}

static int make_stale_dir(const char *path)
{
	char p[PATH_MAX];

	snprintf(p, PATH_MAX, "%s/.stale", path);
	if (xmkdir(p, sd_def_dmode) < 0) {
		sd_err("%s failed, %m", p);
		return SD_RES_EIO;
	}
	return SD_RES_SUCCESS;
}

static int purge_dir(const char *path)
{
	if (purge_directory(path) < 0)
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}

static int purge_stale_dir(const char *path)
{
	char p[PATH_MAX];

	snprintf(p, PATH_MAX, "%s/.stale", path);

	if (purge_directory_async(p) < 0)
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}

int default_cleanup(void)
{
	struct store_cache_entry *entry;
	int ret;

	sd_mutex_lock(&store_cache_lock);
	rb_for_each_entry(entry, &store_cache_root, node) {
		rb_erase(&entry->node, &store_cache_root);
		if (entry->fd != -1) {
			close(entry->fd);
			sys->cache_stat.nr_close++;
		}
		if (entry->path)
			free(entry->path);
		free(entry);
	}
	sd_mutex_unlock(&store_cache_lock);

	ret = for_each_obj_path(purge_stale_dir);
	if (ret != SD_RES_SUCCESS)
		return ret;

	return SD_RES_SUCCESS;
}

static int init_vdi_state(uint64_t oid, const char *wd, uint32_t epoch)
{
	int ret;
	struct sd_inode_header *inode = xzalloc(SD_INODE_HEADER_SIZE);
	struct siocb iocb = {
		.epoch = epoch,
		.buf = inode,
		.length = SD_INODE_HEADER_SIZE,
	};

	ret = default_read(oid, &iocb);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read inode header %016" PRIx64 " %" PRId32
		       "wat %s", oid, epoch, wd);
		goto out;
	}
	add_vdi_state_unordered(oid_to_vid(oid), inode->acl_id,
				inode->nr_copies, vdi_is_snapshot(inode),
				inode->copy_policy, inode->block_size_shift,
				inode->parent_vdi_id);

	if (inode->name[0] == '\0')
		atomic_set_bit(oid_to_vid(oid), sys->vdi_deleted);

	atomic_set_bit(oid_to_vid(oid), sys->vdi_inuse);

	ret = SD_RES_SUCCESS;
out:
	free(inode);
	return ret;
}

static int init_objlist_and_vdi_bitmap(uint64_t oid, const char *wd,
				       uint32_t epoch, uint8_t ec_index,
				       struct vnode_info *vinfo,
				       void *arg)
{
	int ret;
	objlist_cache_insert(oid);

	if (is_vdi_obj(oid)) {
		sd_debug("found the VDI object %016" PRIx64" epoch %"PRIu32
			 " at %s", oid, epoch, wd);
		ret = init_vdi_state(oid, wd, epoch);
		if (ret != SD_RES_SUCCESS)
			return ret;
	}
	return SD_RES_SUCCESS;
}

int default_init(void)
{
	int ret;

	sd_debug("use plain store driver");
	ret = for_each_obj_path(make_stale_dir);
	if (ret != SD_RES_SUCCESS)
		return ret;

	for_each_object_in_stale(init_objlist_and_vdi_bitmap, NULL);

	return for_each_object_in_wd(init_objlist_and_vdi_bitmap, true, NULL);
}

static int default_read_from_path(struct store_cache_entry *entry,
				  const struct siocb *iocb)
{
	int flags = prepare_iocb(entry->oid, iocb, false),
		ret = SD_RES_SUCCESS;
	ssize_t size;

	/*
	 * Make sure oid is in the right place because oid might be misplaced
	 * in a wrong place, due to 'shutdown/restart with less disks' or any
	 * bugs. We need call err_to_sderr() to return EIO if disk is broken.
	 *
	 * For stale path, get_store_stale_path already does default_exist job.
	 */
	if (!is_stale_path(entry->path) &&
	    !default_exist(entry->oid, iocb->ec_index))
		return err_to_sderr(entry->path, entry->oid, ENOENT);

	if (entry->fd < 0) {
		entry->fd = open(entry->path, flags);
		if (entry->fd < 0)
			return err_to_sderr(entry->path, entry->oid, errno);
		sys->cache_stat.nr_open++;
	}

	size = xpread(entry->fd, iocb->buf, iocb->length, iocb->offset);
	if (size < 0) {
		sd_err("failed to read object %016"PRIx64", path=%s, offset=%"
		       PRId32", size=%"PRId32", result=%zd, %m",
		       entry->oid, entry->path,
		       iocb->offset, iocb->length, size);
		ret = err_to_sderr(entry->path, entry->oid, errno);
	}
	if (ret != SD_RES_SUCCESS) {
		close(entry->fd);
		entry->fd = -1;
		sys->cache_stat.nr_close++;
	}
	return ret;
}

int default_read(uint64_t oid, const struct siocb *iocb)
{
	struct store_cache_entry *entry = store_cache_lookup(oid);
	int ret;

	if (!entry)
		return SD_RES_NO_MEM;

	if (entry->fd == -1) {
		ret = get_store_path(oid, iocb->ec_index, &entry->path);
		if (ret < 0) {
			store_cache_remove(entry);
			return SD_RES_NO_MEM;
		}
	} else {
		struct stat st;
		if (fstat(entry->fd, &st) < 0 || st.st_nlink == 0) {
			ret = err_to_sderr(entry->path, entry->oid, ENOENT);
			store_cache_remove(entry);
			return ret;
		}
	}
	ret = default_read_from_path(entry, iocb);

	/*
	 * If the request is against the older epoch, try to read from
	 * the stale directory
	 */
	if (ret == SD_RES_NO_OBJ &&
	    (iocb->wildcard ||
	     (0 < iocb->epoch && iocb->epoch < sys_epoch()))) {
		free(entry->path);
		ret = get_store_stale_path(entry->oid, iocb->epoch,
					   iocb->ec_index, &entry->path);
		if (ret == SD_RES_SUCCESS)
			ret = default_read_from_path(entry, iocb);
		store_cache_remove(entry);
	}
	return ret;
}

int default_create_and_write(uint64_t oid, const struct siocb *iocb)
{
	struct store_cache_entry *entry = store_cache_remove_by_oid(oid);
	char *path, *tmp_path, *dir;
	int flags = prepare_iocb(oid, iocb, true);
	int ret, fd;
	uint32_t len = iocb->length;
	uint32_t object_size = 0;
	size_t obj_size;
	uint64_t offset = iocb->offset;

	sd_debug("%016"PRIx64, oid);
	if (entry) {
		if (entry->fd >= 0)
			close(entry->fd);
		if (entry->path)
			free(entry->path);
		free(entry);
	}
	ret = get_store_path(oid, iocb->ec_index, &path);
	if (ret < 0)
		return SD_RES_NO_MEM;
	ret = get_store_tmp_path(oid, iocb->ec_index, &tmp_path);
	if (ret < 0) {
		free(path);
		return SD_RES_NO_MEM;
	}

	if (uatomic_is_true(&sys->use_journal) &&
	    journal_write_store(oid, iocb->buf, iocb->length,
				iocb->offset, true)
	    != SD_RES_SUCCESS) {
		sd_err("turn off journaling");
		uatomic_set_false(&sys->use_journal);
		flags |= O_SYNC;
		sync();
	}

	fd = open(tmp_path, flags, sd_def_fmode);
	if (fd < 0) {
		sd_err("failed to open %s: %m", tmp_path);
		free(tmp_path);
		ret = err_to_sderr(path, oid, errno);
		free(path);
		return ret;
	}
	sys->cache_stat.nr_open++;

	obj_size = get_store_objsize(oid);

	trim_zero_blocks(iocb->buf, &offset, &len);

	object_size = get_vdi_object_size(oid_to_vid(oid));

	if (offset != 0 || len != get_objsize(oid, object_size)) {
		if (is_sparse_object(oid))
			ret = xftruncate(fd, obj_size);
		else
			ret = prealloc(fd, obj_size);
		if (ret < 0) {
			ret = err_to_sderr(path, oid, errno);
			goto out;
		}
	}

	ret = xpwrite(fd, iocb->buf, len, offset);
	if (ret != len) {
		sd_err("failed to write object. %m");
		ret = err_to_sderr(path, oid, errno);
		goto out;
	}

	ret = rename(tmp_path, path);
	if (ret < 0) {
		sd_err("failed to rename %s to %s: %m", tmp_path, path);
		ret = err_to_sderr(path, oid, errno);
		goto out;
	}

	close(fd);
	sys->cache_stat.nr_close++;
	if (uatomic_is_true(&sys->use_journal) || sys->nosync == true) {
		objlist_cache_insert(oid);
		free(tmp_path);
		free(path);
		return SD_RES_SUCCESS;
	}

	/* dirname() may modify its argument, and tmp_path is longer than path */
	pstrcpy(tmp_path, strlen(tmp_path) + 1, path);
	dir = dirname(tmp_path);
	fd = open(dir, O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		sd_err("failed to open directory %s: %m", dir);
		free(tmp_path);
		ret = err_to_sderr(path, oid, errno);
		free(path);
		return ret;
	}
	sys->cache_stat.nr_open++;
	if (fsync(fd) != 0) {
		sd_err("failed to write directory %s: %m", dir);
		free(tmp_path);
		ret = err_to_sderr(path, oid, errno);
		close(fd);
		sys->cache_stat.nr_close++;
		if (unlink(path) != 0)
			sd_err("failed to unlink %s: %m", path);
		free(path);
		return ret;
	}
	close(fd);
	sys->cache_stat.nr_close++;
	objlist_cache_insert(oid);
	free(tmp_path);
	free(path);
	return SD_RES_SUCCESS;

out:
	if (unlink(tmp_path) != 0)
		sd_err("failed to unlink %s: %m", tmp_path);
	close(fd);
	sys->cache_stat.nr_close++;
	free(tmp_path);
	free(path);
	return ret;
}

int default_link(uint64_t oid, uint32_t tgt_epoch)
{
	struct store_cache_entry *entry = store_cache_remove_by_oid(oid);
	char *path, *stale_path;
	int ret;

	sd_debug("try link %016"PRIx64" from snapshot with epoch %d", oid,
		 tgt_epoch);

	if (entry) {
		if (entry->path)
			free(entry->path);
		if (entry->fd >= 0) {
			close(entry->fd);
			sys->cache_stat.nr_close++;
		}
		free(entry);
	}
	ret = asprintf(&path, "%s/%016"PRIx64,
		       md_get_object_dir(oid), oid);
	if (ret < 0)
		return SD_RES_NO_MEM;

	ret = get_store_stale_path(oid, tgt_epoch, 0, &stale_path);
	if (ret != SD_RES_SUCCESS) {
		sd_warn("get stale path for %016"PRIx64" failed, %s",
			oid, sd_strerror(ret));
		free(path);
		return ret;
	}
	sd_debug("link %016"PRIx64" from %s to %s", oid, stale_path, path);
	if (link(stale_path, path) < 0) {
		/*
		 * Recovery thread and main thread might try to recover the
		 * same object and we might get EEXIST in such case.
		 */
		if (errno == EEXIST)
			goto out;

		sd_debug("failed to link from %s to %s, %m", stale_path, path);
		ret = err_to_sderr(path, oid, errno);
		free(stale_path);
		free(path);
		return ret;
	}
out:
	free(stale_path);
	free(path);
	return SD_RES_SUCCESS;
}

/*
 * For replicated object, if any of the replica belongs to this node, we
 * consider it not stale.
 *
 * For erasure coded object, since every copy is unique and if it migrates to
 * other node(index gets changed even it has some other copy belongs to it)
 * because of hash ring changes, we consider it stale.
 */
static bool oid_stale(uint64_t oid, int ec_index, struct vnode_info *vinfo)
{
	uint32_t i, nr_copies;
	const struct sd_vnode *v;
	bool ret = true;
	const struct sd_vnode *obj_vnodes[SD_MAX_COPIES];

	nr_copies = get_obj_copy_number(oid, vinfo->nr_zones);
	oid_to_vnodes(oid, &vinfo->vroot, nr_copies, obj_vnodes);
	for (i = 0; i < nr_copies; i++) {
		v = obj_vnodes[i];
		if (v && vnode_is_local(v)) {
			if (ec_index < SD_MAX_COPIES) {
				if (i == ec_index)
					ret = false;
			} else {
				ret = false;
			}
			break;
		}
	}

	return ret;
}

static int move_object_to_stale_dir(uint64_t oid, const char *wd,
				    uint32_t epoch, uint8_t ec_index,
				    struct vnode_info *vinfo, void *arg)
{
	char *path, *stale_path;
	uint32_t tgt_epoch = *(uint32_t *)arg;
	int ret;

	/* ec_index from md.c is reliable so we can directly use it */
	if (ec_index < SD_MAX_COPIES) {
		ret = asprintf(&path, "%s/%016"PRIx64"_%d",
			       md_get_object_dir(oid), oid, ec_index);
		if (ret < 0)
			return SD_RES_NO_MEM;
		ret = asprintf(&stale_path, "%s/.stale/%016"PRIx64"_%d.%"PRIu32,
			       md_get_object_dir(oid), oid, ec_index,
			       tgt_epoch);
	} else {
		ret = asprintf(&path, "%s/%016" PRIx64,
			       md_get_object_dir(oid), oid);
		if (ret <  0)
			return SD_RES_NO_MEM;
		ret = asprintf(&stale_path, "%s/.stale/%016"PRIx64".%"PRIu32,
			       md_get_object_dir(oid), oid, tgt_epoch);
	}
	if (ret < 0) {
		free(path);
		return SD_RES_NO_MEM;
	}
	if (unlikely(rename(path, stale_path)) < 0) {
		sd_err("failed to move stale object %" PRIX64 " to %s, %m", oid,
		       path);
		free(path);
		free(stale_path);
		return SD_RES_EIO;
	}

	sd_debug("moved object %016"PRIx64, oid);
	free(path);
	free(stale_path);
	return SD_RES_SUCCESS;
}

static int check_stale_objects(uint64_t oid, const char *wd, uint32_t epoch,
			       uint8_t ec_index, struct vnode_info *vinfo,
			       void *arg)
{
	if (oid_stale(oid, ec_index, vinfo))
		return move_object_to_stale_dir(oid, wd, 0, ec_index,
						NULL, arg);

	return SD_RES_SUCCESS;
}

int default_update_epoch(uint32_t epoch)
{
	sd_assert(epoch);
	return for_each_object_in_wd(check_stale_objects, false, &epoch);
}

int default_format(void)
{
	sd_debug("try get a clean store");
	return for_each_obj_path(purge_dir);
}

int default_remove_object(uint64_t oid, uint8_t ec_index)
{
	struct store_cache_entry *entry = store_cache_remove_by_oid(oid);
	char *path = NULL;
	int ret;

	if (uatomic_is_true(&sys->use_journal))
		journal_remove_object(oid);

	if (entry) {
		path = entry->path;
		if (entry->fd >= 0) {
			close(entry->fd);
			sys->cache_stat.nr_close++;
		}
		free(entry);
	}
	if (!path) {
		ret = get_store_path(oid, ec_index, &path);
		if (ret < 0)
			return SD_RES_NO_MEM;
	}

	if (unlink(path) < 0) {
		if (errno == ENOENT) {
			free(path);
			return SD_RES_NO_OBJ;
		}

		sd_err("failed, %s, %m", path);
		free(path);
		return SD_RES_EIO;
	}

	free(path);
	return SD_RES_SUCCESS;
}

#define SHA1NAME "user.obj.sha1"

static int get_object_sha1(const char *path, uint8_t *sha1)
{
	if (getxattr(path, SHA1NAME, sha1, SHA1_DIGEST_SIZE)
	    != SHA1_DIGEST_SIZE) {
		if (errno == ENODATA)
			sd_debug("sha1 is not cached yet, %s", path);
		else
			sd_err("fail to get xattr, %s", path);
		return -1;
	}

	return 0;
}

static int set_object_sha1(const char *path, const uint8_t *sha1)
{
	int ret;

	ret = setxattr(path, SHA1NAME, sha1, SHA1_DIGEST_SIZE, 0);
	if (ret < 0)
		sd_err("fail to set sha1, %s", path);

	return ret;
}

static int get_object_path(uint64_t oid, uint32_t epoch, char **path)
{
	int ret;

	if (default_exist(oid, 0)) {
		ret = asprintf(path, "%s/%016"PRIx64,
			 md_get_object_dir(oid), oid);
		if (ret < 0)
			return SD_RES_NO_MEM;
	} else {
		ret = get_store_stale_path(oid, epoch, 0, path);
		if (ret == SD_RES_SUCCESS) {
			if (access(*path, F_OK) < 0) {
				ret = SD_RES_EIO;
				if (errno == ENOENT)
					ret = SD_RES_NO_OBJ;
			}
		}
		if (ret != SD_RES_SUCCESS) {
			free(*path);
			*path = NULL;
			return ret;
		}

	}
	return SD_RES_SUCCESS;
}

int default_get_hash(uint64_t oid, uint32_t epoch, uint8_t *sha1)
{
	struct store_cache_entry *entry = store_cache_lookup(oid);
	int ret;
	void *buf;
	struct siocb iocb = {};
	uint32_t length;
	bool is_readonly_obj = oid_is_readonly(oid);

	if (!entry)
		return SD_RES_NO_MEM;

	if (!entry->path) {
		ret = get_object_path(oid, epoch, &entry->path);
		if (ret != SD_RES_SUCCESS) {
			entry->path = NULL;
			return ret;
		}
	}

	if (is_readonly_obj) {
		if (get_object_sha1(entry->path, sha1) == 0) {
			sd_debug("use cached sha1 digest %s",
				 sha1_to_hex(sha1));
			return SD_RES_SUCCESS;
		}
	}

	length = get_store_objsize(oid);
	ret = posix_memalign((void **)&buf, getpagesize(), length);
	if (ret)
		return SD_RES_NO_MEM;

	iocb.epoch = epoch;
	iocb.buf = buf;
	iocb.length = length;

	ret = default_read_from_path(entry, &iocb);
	if (ret != SD_RES_SUCCESS) {
		store_cache_remove(entry);
		return ret;
	}

	get_buffer_sha1(buf, length, sha1);
	free(buf);

	sd_debug("the message digest of %016"PRIx64" at epoch %d is %s", oid,
		 epoch, sha1_to_hex(sha1));

	if (is_readonly_obj)
		set_object_sha1(entry->path, sha1);

	return ret;
}

int default_purge_obj(void)
{
	uint32_t tgt_epoch = get_latest_epoch();

	return for_each_object_in_wd(move_object_to_stale_dir, true,
				     &tgt_epoch);
}

static struct store_driver plain_store = {
	.id = PLAIN_STORE,
	.name = "plain",
	.init = default_init,
	.exist = default_exist,
	.create_and_write = default_create_and_write,
	.write = default_write,
	.read = default_read,
	.link = default_link,
	.update_epoch = default_update_epoch,
	.cleanup = default_cleanup,
	.format = default_format,
	.remove_object = default_remove_object,
	.get_hash = default_get_hash,
	.purge_obj = default_purge_obj,
};

add_store_driver(plain_store);
