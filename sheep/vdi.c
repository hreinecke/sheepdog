/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sheep_priv.h"

struct vdi_state_entry {
	uint32_t vid;
	uint32_t acl;
	unsigned int nr_copies;
	uint8_t block_size_shift;
	bool snapshot;
	bool deleted;
	uint8_t copy_policy;
	uint32_t parent_vid;
	struct rb_node node;

	enum lock_state lock_state;

	/* used for normal locking */
	struct node_id owner;

	/* used for shared locking (iSCSI multipath) */
	int nr_participants;
	enum shared_lock_state participants_state[SD_MAX_COPIES];
	struct node_id participants[SD_MAX_COPIES];

	struct vdi_family_member *family_member;
};

static struct rb_root vdi_state_root = RB_ROOT;
static struct sd_rw_lock vdi_state_lock = SD_RW_LOCK_INITIALIZER;

struct vdi_family_member {
	uint32_t vid, parent_vid;
	struct vdi_family_member *parent;
	struct vdi_state_entry *entry;

	struct list_node roots_list; /* only used for root VDIs */

	struct list_head child_list_head;
	struct list_node child_list_node;
};

static LIST_HEAD(vdi_family_roots);
static LIST_HEAD(vdi_family_temporal_orphans);
static struct sd_mutex vdi_family_mutex = SD_MUTEX_INITIALIZER;

static struct vdi_family_member *lookup_vdi_family_member(uint32_t vid,
				  struct vdi_family_member *family_member)
{
	/* FIXME: more effective data structure */
	struct vdi_family_member *vdi;

	if (family_member->vid == vid)
		return family_member;

	list_for_each_entry(vdi, &family_member->child_list_head,
			    child_list_node) {
		struct vdi_family_member *ret;

		ret = lookup_vdi_family_member(vid, vdi);
		if (ret)
			return ret;
	}

	return NULL;
}

static struct vdi_family_member *lookup_family_member(uint32_t vid)
{
	struct vdi_family_member *vdi, *ret;

	list_for_each_entry(vdi, &vdi_family_roots, roots_list) {
		ret = lookup_vdi_family_member(vid, vdi);
		if (ret)
			return ret;
	}

	return NULL;
}

static void update_vdi_family(uint32_t parent_vid,
			      struct vdi_state_entry *entry, bool unordered)
{
	uint32_t vid = entry->vid;
	struct vdi_family_member *new, *vdi, *parent, *tmp;

	sd_mutex_lock(&vdi_family_mutex);

	if (!parent_vid) {
		new = xzalloc(sizeof(*new));
		new->vid = vid;
		new->entry = entry;
		entry->family_member = new;

		INIT_LIST_NODE(&new->roots_list);
		INIT_LIST_HEAD(&new->child_list_head);
		INIT_LIST_NODE(&new->child_list_node);

		list_add_tail(&new->roots_list, &vdi_family_roots);

		sd_debug("new vid %"PRIx32 " is added as a root VDI", vid);
		goto out;
	}

	new = xzalloc(sizeof(*new));
	new->vid = vid;
	new->parent_vid = parent_vid;
	new->entry = entry;
	entry->family_member = new;

	INIT_LIST_NODE(&new->roots_list);
	INIT_LIST_HEAD(&new->child_list_head);
	INIT_LIST_NODE(&new->child_list_node);

	parent = lookup_family_member(parent_vid);
	if (parent) {
		new->parent = parent;
		goto found;
	}

	if (unordered) {
		sd_debug("parent of VID: %"PRIx32" (%"PRIx32") is not"
			 " initialized yet", vid, parent_vid);

		list_add_tail(&new->child_list_node,
			      &vdi_family_temporal_orphans);
		goto ret;
	}

	panic("parent VID: %"PRIx32" not found", parent_vid);

found:
	list_add_tail(&new->child_list_node, &parent->child_list_head);
	sd_debug("new child vid %"PRIx32" is added to parent %"PRIx32
		 " correctly", vid, parent_vid);

out:
	/* correct children from orphan list */

	list_for_each_entry_safe(vdi, tmp, &vdi_family_temporal_orphans,
				 child_list_node) {
		if (vdi->parent_vid != vid)
			continue;

		list_del(&vdi->child_list_node);
		list_add_tail(&vdi->child_list_node, &new->child_list_head);
		vdi->parent = new;

		sd_debug("new vid %"PRIx32" rescued orphan vid %"PRIx32"",
			 vid, vdi->vid);
	}

ret:
	sd_mutex_unlock(&vdi_family_mutex);
}

/*
 * A VDI can become known before its parent does: dog reserves every vid of a
 * cluster snapshot up front and only links the family together once all the
 * objects are loaded.  Move such a member below its parent instead of leaving
 * it a root of its own, otherwise vid recycling collects it in isolation and
 * drops objects which its descendants still share.
 */
static void reparent_vdi_family(uint32_t parent_vid,
				struct vdi_state_entry *entry)
{
	struct vdi_family_member *member = entry->family_member;
	struct vdi_family_member *parent, *vdi;

	sd_mutex_lock(&vdi_family_mutex);

	if (member->parent && member->parent->vid == parent_vid)
		goto out;	/* already linked to this parent */

	parent = lookup_family_member(parent_vid);
	if (!parent) {
		/*
		 * Unlike update_vdi_family() we don't panic here: the parent
		 * vid can come from a cluster snapshot store we have no
		 * control over, and a missing family link only keeps the vid
		 * from being recycled.
		 */
		sd_err("parent VID: %"PRIx32" of VID: %"PRIx32" not found",
		       parent_vid, member->vid);
		goto out;
	}

	for (vdi = parent; vdi; vdi = vdi->parent) {
		if (vdi != member)
			continue;

		sd_err("VID: %"PRIx32" cannot become a child of its own"
		       " descendant %"PRIx32, member->vid, parent_vid);
		goto out;
	}

	if (list_linked(&member->roots_list))
		list_del(&member->roots_list);
	if (list_linked(&member->child_list_node))
		list_del(&member->child_list_node);

	member->parent_vid = parent_vid;
	member->parent = parent;
	list_add_tail(&member->child_list_node, &parent->child_list_head);

	sd_debug("vid %"PRIx32" is moved below its parent %"PRIx32,
		 member->vid, parent_vid);
out:
	sd_mutex_unlock(&vdi_family_mutex);
}

static main_fn struct vdi_family_member *lookup_root(struct vdi_family_member
						     *member)
{
	if (!member->parent)
		return member;

	return lookup_root(member->parent);
}

static main_fn bool is_all_members_deleted(struct vdi_family_member *member)
{
	struct vdi_family_member *child;

	if (!member->entry->deleted)
		return false;

	list_for_each_entry(child, &member->child_list_head, child_list_node) {
		if (!is_all_members_deleted(child))
			return false;
	}

	return true;
}

/*
 * ec_max_data_strip represent max number of data strips in the cluster. When
 * nr_zones < it, we don't purge the stale objects because for erasure coding,
 * there is only one copy of data.
 */
int ec_max_data_strip;

int sheep_bnode_writer(uint64_t oid, void *mem, unsigned int len,
		       uint64_t offset, uint32_t flags, int copies,
		       int copy_policy, bool create, bool direct)
{
	return sd_write_object(oid, mem, len, offset, create);
}

int sheep_bnode_reader(uint64_t oid, void **mem, unsigned int len,
		       uint64_t offset)
{
	return sd_read_object(oid, *mem, len, offset);
}

static int vdi_state_cmp(const struct vdi_state_entry *a,
			 const struct vdi_state_entry *b)
{
	return intcmp(a->vid, b->vid);
}

static struct vdi_state_entry *vdi_state_search(struct rb_root *root,
						uint32_t vid)
{
	struct vdi_state_entry key = { .vid = vid };

	return rb_search(root, &key, node, vdi_state_cmp);
}

static struct vdi_state_entry *vdi_state_insert(struct rb_root *root,
						struct vdi_state_entry *new)
{
	return rb_insert(root, new, node, vdi_state_cmp);
}

static bool vid_is_snapshot(uint32_t vid)
{
	struct vdi_state_entry *entry;

	sd_read_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);
	sd_rw_unlock(&vdi_state_lock);

	if (!entry) {
		sd_err("No VDI entry for %" PRIx32 " found", vid);
		return 0;
	}

	return entry->snapshot;
}

bool oid_is_readonly(uint64_t oid)
{
	/* we allow changing snapshot attributes */
	if (!is_data_obj(oid))
		return false;

	return vid_is_snapshot(oid_to_vid(oid));
}

int get_vdi_copy_number(uint32_t vid)
{
	struct vdi_state_entry *entry;

	sd_read_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);
	sd_rw_unlock(&vdi_state_lock);

	if (!entry) {
		sd_alert("copy number for %" PRIx32 " not found, set %d", vid,
			 sys->cinfo.nr_copies);
		return sys->cinfo.nr_copies;
	}

	return entry->nr_copies;
}

int get_vdi_copy_policy(uint32_t vid)
{
	struct vdi_state_entry *entry;

	sd_read_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);
	sd_rw_unlock(&vdi_state_lock);

	if (!entry) {
		sd_alert("copy policy for %" PRIx32 " not found, set %d", vid,
			 sys->cinfo.copy_policy);
		return sys->cinfo.copy_policy;
	}

	return entry->copy_policy;
}

uint32_t get_vdi_object_size(uint32_t vid)
{
	struct vdi_state_entry *entry;
	uint32_t object_size;

	sd_read_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);
	sd_rw_unlock(&vdi_state_lock);

	if (!entry) {
		object_size = UINT32_C(1) << sys->cinfo.block_size_shift;
		sd_alert("object_size for %" PRIx32 " not found, set %" PRIu32,
			 vid, object_size);
		return object_size;
	}

	object_size = UINT32_C(1) << entry->block_size_shift;
	return object_size;
}

uint8_t get_vdi_block_size_shift(uint32_t vid)
{
	struct vdi_state_entry *entry;

	sd_read_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);
	sd_rw_unlock(&vdi_state_lock);

	if (!entry) {
		sd_alert("block_size_shift for %" PRIx32
			 " not found, set %" PRIu8, vid,
			 sys->cinfo.block_size_shift);
		return sys->cinfo.block_size_shift;
	}

	return entry->block_size_shift;
}

int get_obj_copy_number(uint64_t oid, int nr_zones)
{
	return min(get_vdi_copy_number(oid_to_vid(oid)), nr_zones);
}

int get_req_copy_number(struct request *req)
{
	int nr_copies;

	nr_copies = min((int)req->rq.obj.copies, req->vinfo->nr_zones);
	if (!nr_copies)
		nr_copies = get_obj_copy_number(req->rq.obj.oid,
						req->vinfo->nr_zones);

	return nr_copies;
}

static int do_add_vdi_state(uint32_t vid, uint32_t acl, int nr_copies,
			    bool snapshot, uint8_t cp, uint8_t block_size_shift,
			    uint32_t parent_vid, bool unordered)
{
	struct vdi_state_entry *entry, *old;

	entry = xzalloc(sizeof(*entry));
	entry->vid = vid;
	entry->acl = acl;
	entry->nr_copies = nr_copies;
	entry->snapshot = snapshot;
	entry->copy_policy = cp;
	entry->block_size_shift = block_size_shift;
	entry->parent_vid = parent_vid;

	entry->lock_state = LOCK_STATE_UNLOCKED;
	memset(&entry->owner, 0, sizeof(struct node_id));

	if (cp) {
		int d;
		static struct sd_mutex m = SD_MUTEX_INITIALIZER;

		ec_policy_to_dp(cp, &d, NULL);

		sd_mutex_lock(&m);
		ec_max_data_strip = max(d, ec_max_data_strip);
		sd_mutex_unlock(&m);
	}

	sd_debug("%" PRIx32 ", acl %" PRIx32 ", copies %d, copy policy%d, bss %"PRIu8", parent %"PRIx32,
		 vid, acl, nr_copies, cp, block_size_shift, parent_vid);

	sd_write_lock(&vdi_state_lock);
	old = vdi_state_insert(&vdi_state_root, entry);
	if (old) {
		free(entry);
		entry = old;
		entry->nr_copies = nr_copies;
		entry->snapshot = snapshot;
		entry->copy_policy = cp;
		entry->block_size_shift = block_size_shift;

		if (entry->acl != acl) {
			sd_warn("caution, updating ACL of VID: %" PRIx32" (old ACL %" PRIx32 ", new ACL %" PRIx32 ")",
				entry->vid, entry->acl, acl);
			entry->acl = acl;
		}
		if (parent_vid) {
			if (!snapshot)
				sd_warn("caution, updating parent VID of VID: %"
					PRIx32 " (old parent VID: %" PRIx32
					", new parent VID: %"PRIx32 ")", vid,
					entry->parent_vid, parent_vid);

			entry->parent_vid = parent_vid;
		}
	}

	if (sys->cinfo.flags & SD_CLUSTER_FLAG_RECYCLE_VID) {
		/*
		 * A vid can be registered without a parent and be told about
		 * its parent only later on, so keep the family tree in sync
		 * instead of building it once and for all.
		 */
		if (!entry->family_member)
			update_vdi_family(parent_vid, entry, unordered);
		else if (parent_vid)
			reparent_vdi_family(parent_vid, entry);
	}

	sd_rw_unlock(&vdi_state_lock);

	return SD_RES_SUCCESS;
}

int add_vdi_state(uint32_t vid, uint32_t acl, int nr_copies, bool snapshot,
		  uint8_t cp, uint8_t block_size_shift, uint32_t parent_vid)
{
	return do_add_vdi_state(vid, acl, nr_copies, snapshot, cp,
				block_size_shift, parent_vid, false);
}

int add_vdi_state_unordered(uint32_t vid, uint32_t acl, int nr_copies,
		bool snapshot, uint8_t cp, uint8_t block_size_shift,
		uint32_t parent_vid)
{
	return do_add_vdi_state(vid, acl, nr_copies, snapshot, cp,
				block_size_shift, parent_vid, true);
}

int fill_vdi_state_list(const struct sd_req *hdr,
			struct sd_rsp *rsp, void *data)
{
#define DEFAULT_VDI_STATE_COUNT 512
	int last = 0, end = DEFAULT_VDI_STATE_COUNT;
	struct vdi_state_entry *entry;
	struct vdi_state *vs = xzalloc(end * sizeof(struct vdi_state));

	sd_read_lock(&vdi_state_lock);
	rb_for_each_entry(entry, &vdi_state_root, node) {
		if (last >= end) {
			end *= 2;
			vs = xrealloc(vs, end * sizeof(struct vdi_state));
		}

		vs[last].vid = entry->vid;
		vs[last].acl = entry->acl;
		vs[last].nr_copies = entry->nr_copies;
		vs[last].snapshot = entry->snapshot;
		vs[last].deleted = entry->deleted;
		vs[last].copy_policy = entry->copy_policy;
		vs[last].block_size_shift = entry->block_size_shift;
		vs[last].lock_state = entry->lock_state;
		vs[last].lock_owner = entry->owner;
		vs[last].nr_participants = entry->nr_participants;
		vs[last].parent_vid = entry->parent_vid;
		for (int i = 0; i < vs[last].nr_participants; i++) {
			vs[last].participants_state[i] =
				entry->participants_state[i];
			vs[last].participants[i] = entry->participants[i];
		}

		last++;
	}
	sd_rw_unlock(&vdi_state_lock);

	if (hdr->data_length < last * sizeof(struct vdi_state)) {
		free(vs);
		sd_warn("response buffer length %u too small, need %lu",
			hdr->data_length, last * sizeof(struct vdi_state));
		return SD_RES_BUFFER_SMALL;
	}

	rsp->data_length = last * sizeof(struct vdi_state);
	memcpy(data, vs, rsp->data_length);
	free(vs);
	return SD_RES_SUCCESS;
}

static struct vdi_state *fill_vdi_state_list_with_alloc(int *result_nr)
{
	struct vdi_state *vs;
	struct vdi_state_entry *entry;
	int i = 0, nr = 0;

	sd_read_lock(&vdi_state_lock);
	rb_for_each_entry(entry, &vdi_state_root, node) {
		nr++;
	}

	vs = xcalloc(nr, sizeof(*vs));
	rb_for_each_entry(entry, &vdi_state_root, node) {
		vs[i].vid = entry->vid;
		vs[i].acl = entry->acl;
		vs[i].nr_copies = entry->nr_copies;
		vs[i].snapshot = entry->snapshot;
		vs[i].deleted = entry->deleted;
		vs[i].copy_policy = entry->copy_policy;
		vs[i].block_size_shift = entry->block_size_shift;
		vs[i].lock_state = entry->lock_state;
		vs[i].lock_owner = entry->owner;
		vs[i].nr_participants = entry->nr_participants;
		for (int j = 0; j < vs[i].nr_participants; j++) {
			vs[i].participants_state[j] =
				entry->participants_state[j];
			vs[i].participants[j] = entry->participants[j];
		}

		sd_assert(i < nr);
		i++;
	}

	sd_rw_unlock(&vdi_state_lock);

	*result_nr = nr;
	return vs;
}

static inline bool vdi_is_deleted(struct sd_inode *inode)
{
	return *inode->header.name == '\0';
}

int vdi_exist(uint32_t vid)
{
	struct sd_inode *inode;
	int ret;

	inode = xzalloc(sizeof(*inode));
	ret = sd_read_object(vid_to_vdi_oid(vid), (char *)inode,
			     sizeof(*inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("fail to read vdi inode (%" PRIx32 ")", vid);
		ret = 0;
		goto out;
	}

	if (vdi_is_deleted(inode)) {
		ret = 0;
		goto out;
	}
	ret = 1;
out:
	free(inode);
	return ret;
}

static bool is_valid_shared_state(struct vdi_state_entry *entry)
{
	struct node_id *current_owner = NULL;	/* modified */

	for (int i = 0; i < entry->nr_participants; i++) {
		enum shared_lock_state state = entry->participants_state[i];

		if (state == SHARED_LOCK_STATE_MODIFIED) {
			if (current_owner) {
				sd_err("invalid shared state, two (or more)"
				       " nodes are owning VDI %"PRIx32":"
				       " %s and %s", entry->vid,
				       node_id_to_str(current_owner, false),
				       node_id_to_str(&entry->participants[i], false));

				return false;
			}

			current_owner = &entry->participants[i];
		}
	}

	return true;
}

static bool is_modified(struct vdi_state_entry *entry)
{
	if (!is_valid_shared_state(entry))
		panic("invalid shared state");

	for (int i = 0; i < entry->nr_participants; i++) {
		if (SHARED_LOCK_STATE_MODIFIED == entry->participants_state[i])
			return true;
	}

	return false;
}

static bool add_new_participant(struct vdi_state_entry *entry,
				const struct node_id *owner)
{
	int idx;

	if (entry->lock_state == LOCK_STATE_UNLOCKED) {
		sd_assert(!entry->nr_participants);

		sd_debug("%s is first owner of %"PRIx32,
			 node_id_to_str(owner, false), entry->vid);

		entry->nr_participants = 1;
		memcpy(&entry->participants[0], owner, sizeof(*owner));
		entry->participants_state[0] = SHARED_LOCK_STATE_MODIFIED;
		entry->lock_state = LOCK_STATE_SHARED;

		return true;
	}

	sd_assert(entry->lock_state == LOCK_STATE_SHARED);
	sd_assert(0 < entry->nr_participants);

	if (entry->nr_participants == SD_MAX_COPIES) {
		sd_err("VDI: %"PRIx32 " already has SD_MAX_COPIES participants",
			entry->vid);
		return false;
	}

	for (int i = 0; i < entry->nr_participants; i++) {
		if (node_id_cmp(&entry->participants[i], owner))
			continue;

		sd_err("%s is already locking %"PRIx32,
		       node_id_to_str(owner, false), entry->vid);
		return false;
	}

	idx = entry->nr_participants;
	memcpy(&entry->participants[idx], owner, sizeof(*owner));
	entry->participants_state[idx] =
		is_modified(entry) ?
		SHARED_LOCK_STATE_INVALIDATED : SHARED_LOCK_STATE_SHARED;
	entry->nr_participants++;

	sd_debug("new participant %s (%d) joined to VID: %"PRIx32", state is %d",
		 node_id_to_str(&entry->participants[idx], false), idx,
		 entry->vid, entry->participants_state[idx]);

	return true;
}

static void del_participant(struct vdi_state_entry *entry,
			    const struct node_id *owner, bool err_msg)
{
	int idx = -1;

	if (entry->nr_participants == 0)
		return;

	for (int i = 0; i < entry->nr_participants; i++) {
		if (!node_id_cmp(&entry->participants[i], owner)) {
			idx = i;
			break;
		}
	}

	if (idx == -1) {
		if (err_msg)
			sd_err("unknown participants: %s",
			       node_id_to_str(owner, false));

		return;
	}

	for (int i = idx; i < entry->nr_participants - 1; i++) {
		memcpy(&entry->participants[i], &entry->participants[i + 1],
		       sizeof(entry->participants[i]));
		entry->participants_state[i] = entry->participants_state[i + 1];
	}
	entry->nr_participants--;

	sd_debug("participant: %s is deleted, current participants are below:",
		 node_id_to_str(owner, false));
	for (int i = 0; i < entry->nr_participants; i++)
		sd_debug("%d: %s", i,
			 node_id_to_str(&entry->participants[i], false));

	if (!entry->nr_participants)
		entry->lock_state = LOCK_STATE_UNLOCKED;
}

int vdi_lock(uint32_t vid, const struct node_id *owner, uint32_t acl)
{
	struct vdi_state_entry *entry;
	int ret = SD_RES_NO_VDI;

	sd_write_lock(&vdi_state_lock);

	entry = vdi_state_search(&vdi_state_root, vid);
	if (!entry) {
		sd_err("no vdi state entry of %"PRIx32" found", vid);
		goto out;
	}

	if (acl == LOCK_TYPE_NORMAL) {
		if (entry->acl != LOCK_TYPE_NORMAL) {
			sd_info("VDI %"PRIx32" can only be locked with ACL %"PRIx32,
				vid, entry->acl);
			ret = SD_RES_VDI_DENIED;
			goto out;
		}

		switch (entry->lock_state) {
		case LOCK_STATE_UNLOCKED:
			entry->lock_state = LOCK_STATE_LOCKED;
			memcpy(&entry->owner, owner, sizeof(*owner));
			sd_info("VDI %"PRIx32" is locked", vid);
			ret = SD_RES_SUCCESS;
			goto out;
		case LOCK_STATE_LOCKED:
			sd_info("VDI %"PRIx32" is already locked", vid);
			ret = SD_RES_VDI_LOCKED;
			break;
		case LOCK_STATE_SHARED:
			sd_info("VDI %"PRIx32" is already locked by %"PRIx32,
				vid, entry->acl);
			ret = SD_RES_VDI_DENIED;
			break;
		default:
			sd_alert("lock state of VDI (%"PRIx32") is unknown: %d",
				 vid, entry->lock_state);
			break;
		}
	} else {		/* LOCK_TYPE_SHARED */
		switch (entry->lock_state) {
		case LOCK_STATE_UNLOCKED:
		case LOCK_STATE_SHARED:
			if (entry->acl != acl) {
				sd_info("VDI %"PRIx32" is already locked by %"PRIx32,
					vid, entry->acl);
				ret = SD_RES_VDI_DENIED;
			} else if (add_new_participant(entry, owner))
				ret = SD_RES_SUCCESS;
			else
				ret = SD_RES_VDI_LOCKED;
			break;
		case LOCK_STATE_LOCKED:
			sd_info("VDI %"PRIx32" is already locked as normal"
				" mode", vid);
			ret = SD_RES_VDI_LOCKED;
			break;
		default:
			sd_alert("lock state of VDI (%"PRIx32") is unknown: %d",
				 vid, entry->lock_state);
			break;
		}
	}

out:
	sd_rw_unlock(&vdi_state_lock);
	return ret;
}

int vdi_unlock(uint32_t vid, const struct node_id *owner, uint32_t acl)
{
	struct vdi_state_entry *entry;
	int ret = SD_RES_NO_VDI;

	sd_write_lock(&vdi_state_lock);

	entry = vdi_state_search(&vdi_state_root, vid);
	if (!entry) {
		sd_err("no vdi state entry of %"PRIx32" found", vid);
		goto out;
	}

	if (acl == LOCK_TYPE_NORMAL) {
		switch (entry->lock_state) {
		case LOCK_STATE_UNLOCKED:
			sd_err("unlocking unlocked VDI: %"PRIx32, vid);
			ret = SD_RES_INVALID_PARMS;
			break;
		case LOCK_STATE_LOCKED:
			entry->lock_state = LOCK_STATE_UNLOCKED;
			memset(&entry->owner, 0, sizeof(entry->owner));
			ret = SD_RES_SUCCESS;
			break;
		default:
			sd_alert("lock state of VDI (%"PRIx32") is unknown: %d",
				 vid, entry->lock_state);
			ret = SD_RES_SYSTEM_ERROR;
			break;
		}
	} else {		/* LOCK_TYPE_SHARED */
		switch (entry->lock_state) {
		case LOCK_STATE_UNLOCKED:
			sd_alert("leaving from unlocked VDI: %"PRIx32, vid);
			ret = SD_RES_SUCCESS;
			break;
		case LOCK_STATE_SHARED:
			if (acl != entry->acl) {
				sd_info("VDI %"PRIx32" is locked by %"PRIx32,
					vid, entry->acl);
				ret = SD_RES_VDI_DENIED;
			} else {
				del_participant(entry, owner, true);
				ret = SD_RES_SUCCESS;
			}
			break;
		case LOCK_STATE_LOCKED:
			sd_alert("leaving from normally locked VDI %"PRIx32,
				 vid);
			ret = SD_RES_VDI_LOCKED;
			break;
		default:
			sd_alert("lock state of VDI (%"PRIx32") is unknown: %d",
				 vid, entry->lock_state);
			break;
		}
	}
out:
	sd_rw_unlock(&vdi_state_lock);
	return ret;
}

/*
 * Check if the ACL of a VDI can be changed.  Called on the node which is
 * handling SD_OP_ALTER_VDI_ACL before the inode object is rewritten.
 */
int vdi_can_alter_acl(uint32_t vid, uint32_t acl)
{
	struct vdi_state_entry *entry;
	int ret = SD_RES_NO_VDI;

	sd_read_lock(&vdi_state_lock);

	entry = vdi_state_search(&vdi_state_root, vid);
	if (!entry) {
		sd_err("no vdi state entry of %"PRIx32" found", vid);
		goto out;
	}

	if (entry->acl != acl) {
		sd_info("VDI %"PRIx32" belongs to ACL %"PRIx32", not %"PRIx32,
			vid, entry->acl, acl);
		ret = SD_RES_VDI_DENIED;
		goto out;
	}

	if (entry->lock_state != LOCK_STATE_UNLOCKED) {
		sd_info("VDI %"PRIx32" is locked, cannot alter its ACL", vid);
		ret = SD_RES_VDI_LOCKED;
		goto out;
	}

	ret = SD_RES_SUCCESS;
out:
	sd_rw_unlock(&vdi_state_lock);
	return ret;
}

/*
 * Apply the ACL of an already rewritten inode object to the VDI state.  The
 * inode object is authoritative here, so the new ACL is applied even if this
 * node disagrees about the old one.
 */
int vdi_alter_acl(uint32_t vid, uint32_t old_acl, uint32_t new_acl)
{
	struct vdi_state_entry *entry;
	int ret = SD_RES_NO_VDI;

	sd_write_lock(&vdi_state_lock);

	entry = vdi_state_search(&vdi_state_root, vid);
	if (!entry) {
		sd_err("no vdi state entry of %"PRIx32" found", vid);
		goto out;
	}

	if (entry->acl != old_acl)
		sd_warn("VDI %"PRIx32" has ACL %"PRIx32", expected %"PRIx32,
			vid, entry->acl, old_acl);

	sd_info("ACL of VDI %"PRIx32" is set to %"PRIx32", the old one was %"
		PRIx32, vid, new_acl, entry->acl);
	entry->acl = new_acl;
	ret = SD_RES_SUCCESS;
out:
	sd_rw_unlock(&vdi_state_lock);
	return ret;
}

void apply_vdi_lock_state(struct vdi_state *vs)
{
	struct vdi_state_entry *entry;

	sd_write_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vs->vid);
	if (!entry) {
		sd_err("no vdi state entry of %"PRIx32" found", vs->vid);
		goto out;
	}
	if (entry->acl != LOCK_TYPE_NORMAL) {
		sd_err("VDI %"PRIx32" locked by ACL %"PRIx32", cannot update",
		       vs->vid, entry->acl);
		goto out;
	}
	entry->lock_state = vs->lock_state;
	memcpy(&entry->owner, &vs->lock_owner, sizeof(vs->lock_owner));

	entry->nr_participants = vs->nr_participants;
	memcpy(entry->participants_state, vs->participants_state,
	       sizeof(entry->participants_state[0]) * SD_MAX_COPIES);
	memcpy(entry->participants, vs->participants,
	       sizeof(entry->participants[0]) * SD_MAX_COPIES);

out:
	sd_rw_unlock(&vdi_state_lock);
}

static void apply_vdi_lock_state_shared(uint32_t vid, uint32_t acl, bool lock,
					struct node_id *locker)
{
	struct vdi_state_entry *entry;

	sd_write_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);
	if (!entry) {
		sd_err("no vdi state entry of %"PRIx32" found", vid);
		goto out;
	}

	if (entry->acl == LOCK_TYPE_NORMAL) {
		sd_err("VDI %"PRIx32" has an exclusive lock, cannot update",
		       vid);
		goto out;
	} else if (entry->acl == acl) {
		sd_err("VDI %"PRIx32" locked by ACL %"PRIx32", cannot update",
		       vid, entry->acl);
		goto out;
	}

	if (lock)
		add_new_participant(entry, locker);
	else
		del_participant(entry, locker, true);

out:
	sd_rw_unlock(&vdi_state_lock);
}

static LIST_HEAD(logged_vdi_ops);

struct vdi_op_log {
	bool lock;
	uint32_t acl;
	uint32_t vid;
	struct node_id owner;

	struct list_node list;
};

void log_vdi_op_lock(uint32_t vid, const struct node_id *owner, uint32_t acl)
{
	struct vdi_op_log *op;

	op = xzalloc(sizeof(*op));
	op->lock = true;
	op->acl = acl;
	op->vid = vid;
	memcpy(&op->owner, owner, sizeof(*owner));
	INIT_LIST_NODE(&op->list);
	list_add_tail(&op->list, &logged_vdi_ops);
}

void log_vdi_op_unlock(uint32_t vid, const struct node_id *owner, uint32_t acl)
{
	struct vdi_op_log *op;

	op = xzalloc(sizeof(*op));
	op->lock = false;
	op->acl = acl;
	op->vid = vid;
	memcpy(&op->owner, owner, sizeof(*owner));
	INIT_LIST_NODE(&op->list);
	list_add_tail(&op->list, &logged_vdi_ops);
}

void play_logged_vdi_ops(void)
{
	struct vdi_op_log *op;

	list_for_each_entry(op, &logged_vdi_ops, list) {
		struct vdi_state entry;

		memset(&entry, 0, sizeof(entry));
		entry.vid = op->vid;

		if (op->acl == LOCK_TYPE_NORMAL) {
			memcpy(&entry.lock_owner, &op->owner,
			       sizeof(op->owner));
			if (op->lock)
				entry.lock_state = LOCK_STATE_LOCKED;
			else
				entry.lock_state = LOCK_STATE_UNLOCKED;

			apply_vdi_lock_state(&entry);
		} else {
			apply_vdi_lock_state_shared(op->vid, op->acl,
						    op->lock, &op->owner);
		}
	}
}

worker_fn bool is_refresh_required(uint32_t vid)
{
	struct vdi_state_entry *entry;
	bool ret = false;

	sd_read_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);

	if (!entry) {
		sd_alert("VID: %"PRIx32" doesn't exist", vid);
		goto out;
	}

	if (entry->lock_state != LOCK_STATE_SHARED)
		goto out;

	for (int i = 0; i < entry->nr_participants; i++) {
		if (node_id_cmp(&entry->participants[i], &sys->this_node.nid))
			continue;

		if (entry->participants_state[i] ==
		    SHARED_LOCK_STATE_INVALIDATED)
			ret = true;
		goto out;
	}

	sd_alert("this node isn't locking VID: %"PRIx32, vid);

out:
	sd_rw_unlock(&vdi_state_lock);

	return ret;
}

worker_fn void validate_myself(uint32_t vid)
{
	struct vdi_state_entry *entry;
	struct sd_req hdr;
	int ret;

	sd_read_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);

	if (!entry) {
		sd_alert("VID: %"PRIx32" doesn't exist", vid);
		goto out;
	}

	if (entry->lock_state != LOCK_STATE_SHARED)
		goto out;

	for (int i = 0; i < entry->nr_participants; i++) {
		if (node_id_cmp(&entry->participants[i], &sys->this_node.nid))
			continue;

		if (entry->participants_state[i] !=
		    SHARED_LOCK_STATE_INVALIDATED)
			goto out;

		goto validate;
	}

	sd_alert("this node isn't locking VID: %"PRIx32, vid);
	goto out;

validate:
	sd_rw_unlock(&vdi_state_lock);

	sd_init_req(&hdr, SD_OP_INODE_COHERENCE);
	hdr.inode_coherence.vid = vid;
	hdr.inode_coherence.validate = 1;
	ret = sheep_exec_req(&sys->this_node.nid, &hdr, NULL);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to validate VID: %"PRIx32" by %s",
		       vid, node_to_str(&sys->this_node));
	}

	return;

out:
	sd_rw_unlock(&vdi_state_lock);
}

worker_fn void invalidate_other_nodes(uint32_t vid)
{
	struct vdi_state_entry *entry;
	struct sd_req hdr;
	int ret;

	sd_read_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);

	if (!entry) {
		sd_alert("VID: %"PRIx32" doesn't exist", vid);
		goto out;
	}

	if (entry->lock_state != LOCK_STATE_SHARED)
		goto out;

	for (int i = 0; i < entry->nr_participants; i++) {
		if (node_id_cmp(&entry->participants[i], &sys->this_node.nid))
			continue;

		if (entry->participants_state[i] !=
		    SHARED_LOCK_STATE_MODIFIED)
			goto invalidate;

		/* already owned by myself */
		goto out;
	}

	sd_alert("this node isn't locking VID: %"PRIx32, vid);
	goto out;

invalidate:
	sd_rw_unlock(&vdi_state_lock);

	sd_init_req(&hdr, SD_OP_INODE_COHERENCE);
	hdr.inode_coherence.vid = vid;
	hdr.inode_coherence.validate = 0;
	ret = sheep_exec_req(&sys->this_node.nid, &hdr, NULL);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to validate VID: %"PRIx32" by %s",
		       vid, node_to_str(&sys->this_node));
	}

	return;

out:
	sd_rw_unlock(&vdi_state_lock);
}

main_fn int inode_coherence_update(uint32_t vid, bool validate,
				   const struct node_id *sender)
{
	struct vdi_state_entry *entry;
	bool invalidated = false;
	int ret = SD_RES_SUCCESS;

	sd_write_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);

	if (!entry) {
		sd_alert("VID: %"PRIx32" doesn't exist", vid);
		ret = SD_RES_NO_VDI;
		goto out;
	}

	sd_assert(entry->lock_state == LOCK_STATE_SHARED);

	if (validate) {
		for (int i = 0; i < entry->nr_participants; i++) {
			if (node_id_cmp(&entry->participants[i], sender)
			    && entry->participants_state[i] ==
			    SHARED_LOCK_STATE_INVALIDATED)
				/*
				 * don't validate other invalidated, they need
				 * to validate by themselves
				 */
				continue;

			entry->participants_state[i] = SHARED_LOCK_STATE_SHARED;
		}
	} else {
		for (int i = 0; i < entry->nr_participants; i++) {
			if (node_id_cmp(&entry->participants[i], sender))
				entry->participants_state[i] =
					SHARED_LOCK_STATE_INVALIDATED;
			else {
				entry->participants_state[i] =
					SHARED_LOCK_STATE_MODIFIED;
				invalidated = true;
			}
		}

		if (!invalidated) {
			sd_err("%s isn't participating in VID: %"PRIx32,
			       node_id_to_str(sender, false), vid);
			ret = SD_RES_NO_VDI;
		}
	}

out:
	sd_rw_unlock(&vdi_state_lock);
	return ret;
}

main_fn void remove_node_from_participants(const struct node_id *left)
{
	struct vdi_state_entry *entry;

	sd_write_lock(&vdi_state_lock);
	rb_for_each_entry(entry, &vdi_state_root, node) {
		del_participant(entry, left, false);
	}
	sd_rw_unlock(&vdi_state_lock);

}

static struct sd_inode *alloc_inode(const struct vdi_iocb *iocb,
				    uint32_t new_snapid, uint32_t new_vid,
				    uint32_t *data_vdi_id,
				    struct generation_reference *gref)
{
	struct sd_inode *new = xzalloc(sizeof(*new));
	unsigned long block_size = (UINT32_C(1) << iocb->block_size_shift);
	uuid_t uuid;

	pstrcpy(new->header.name, sizeof(new->header.name), iocb->name);
	new->header.vdi_id = new_vid;
	new->header.create_time = iocb->time;
	new->header.vdi_size = iocb->size;
	new->header.copy_policy = iocb->copy_policy;
	new->header.store_policy = iocb->store_policy;
	new->header.nr_copies = iocb->nr_copies;
	new->header.acl_id = iocb->acl;
	new->header.block_size_shift =
		find_next_bit(&block_size, BITS_PER_LONG, 0);
	new->header.snap_id = new_snapid;
	uuid_generate(uuid);
	memcpy(new->header.uuid, (uint8_t *)uuid, sizeof(uuid));
	new->header.parent_vdi_id = iocb->base_vid;
	if (data_vdi_id)
		sd_inode_copy_vdis(sheep_bnode_writer, sheep_bnode_reader,
				   data_vdi_id, iocb->store_policy,
				   iocb->nr_copies, iocb->copy_policy, new);
	else if (sd_store_policy_is_hyper(&new->header))
		sd_inode_init(new->data_vdi_id, 1);

	if (gref) {
		sd_assert(data_vdi_id);

		for (int i = 0; i < SD_INODE_DATA_INDEX; i++) {
			if (!data_vdi_id[i])
				continue;

			new->gref[i].generation = gref[i].generation + 1;
		}
	}

	return new;
}

/* Create a fresh vdi */
static int create_vdi(const struct vdi_iocb *iocb, uint32_t new_snapid,
		      uint32_t new_vid)
{
	struct sd_inode *new = alloc_inode(iocb, new_snapid, new_vid, NULL,
					   NULL);
	int ret;

	sd_debug("%s: size %" PRIu64 ", new_vid %" PRIx32 ", copies %d, "
		 "snapid %" PRIu32 " copy policy %"PRIu8 " store policy %"PRIu8
		 " block_size_shift %"PRIu8, iocb->name, iocb->size, new_vid,
		  iocb->nr_copies, new_snapid, new->header.copy_policy,
		  new->header.store_policy, iocb->block_size_shift);

	ret = sd_write_object(vid_to_vdi_oid(new_vid), (char *)new,
			      sizeof(*new), 0, true);
	if (ret != SD_RES_SUCCESS)
		ret = SD_RES_VDI_WRITE;

	free(new);
	return ret;
}

/*
 * Create a clone vdi from the existing snapshot
 *
 * This creates a working vdi 'new' based on the snapshot 'base'.  For example:
 *
 * [before]
 *                base
 *            o----o----o----x
 *
 * [after]
 *                base
 *            o----o----o----x
 *                  \
 *                   x new
 * x: working vdi
 * o: snapshot vdi
 */
static int clone_vdi(const struct vdi_iocb *iocb, uint32_t new_snapid,
		     uint32_t new_vid, uint32_t base_vid)
{
	struct sd_inode *new = NULL, *base = xzalloc(sizeof(*base));
	int ret;

	sd_debug("%s: size %" PRIu64 ", vid %" PRIx32 ", base %" PRIx32 ", "
		 "copies %d, block_size_shift %" PRIu8 ", snapid %" PRIu32,
		 iocb->name, iocb->size, new_vid, base_vid,
		 iocb->nr_copies, iocb->block_size_shift, new_snapid);

	ret = sd_read_object(vid_to_vdi_oid(base_vid), (char *)base,
			     sizeof(*base), 0);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_BASE_VDI_READ;
		goto out;
	}

	/* TODO: multiple sd_write_object should be performed atomically */

	for (int i = 0; i < ARRAY_SIZE(base->gref); i++) {
		if (base->data_vdi_id[i])
			base->gref[i].count++;
	}

	ret = sd_write_object(vid_to_vdi_oid(base_vid), (char *)base->gref,
			      sizeof(base->gref),
			      offsetof(struct sd_inode, gref), false);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_BASE_VDI_WRITE;
		goto out;
	}

	/* create a new vdi */
	new = alloc_inode(iocb, new_snapid, new_vid, base->data_vdi_id,
			  base->gref);
	ret = sd_write_object(vid_to_vdi_oid(new_vid), (char *)new,
			      sizeof(*new), 0, true);
	if (ret != SD_RES_SUCCESS)
		ret = SD_RES_VDI_WRITE;

out:
	free(new);
	free(base);
	return ret;
}

/*
 * Create a snapshot vdi
 *
 * This makes the current working vdi 'base' a snapshot, and create a working
 * vdi 'new'.  For example:
 *
 * [before]
 *            o----o----o----x base
 *
 * [after]
 *                          base
 *            o----o----o----o----x new
 *
 * x: working vdi
 * o: snapshot vdi
 */
static int snapshot_vdi(const struct vdi_iocb *iocb, uint32_t new_snapid,
			uint32_t new_vid, uint32_t base_vid)
{
	struct sd_inode *new = NULL, *base = xzalloc(sizeof(*base));
	int ret;

	sd_debug("%s: size %" PRIu64 ", vid %" PRIx32 ", base %" PRIx32 ", "
		 "copies %d, block_size_shift %"PRIu8 ", snapid %" PRIu32,
		 iocb->name, iocb->size, new_vid, base_vid,
		 iocb->nr_copies, iocb->block_size_shift, new_snapid);

	ret = sd_read_object(vid_to_vdi_oid(base_vid), (char *)base,
			     sizeof(*base), 0);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_BASE_VDI_READ;
		goto out;
	}

	/* TODO: multiple sd_write_object should be performed atomically */

	/* update a base vdi */
	base->header.snap_ctime = iocb->time;

	for (int i = 0; i < ARRAY_SIZE(base->gref); i++) {
		if (base->data_vdi_id[i])
			base->gref[i].count++;
	}

	ret = sd_write_object(vid_to_vdi_oid(base_vid), (char *)base,
			      sizeof(*base), 0, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("updating gref of VDI %" PRIx32 "failed", base_vid);
		ret = SD_RES_BASE_VDI_WRITE;
		goto out;
	}

	/* create a new vdi */
	new = alloc_inode(iocb, new_snapid, new_vid, base->data_vdi_id,
			  base->gref);
	ret = sd_write_object(vid_to_vdi_oid(new_vid), (char *)new,
			      sizeof(*new), 0, true);
	if (ret != SD_RES_SUCCESS)
		ret = SD_RES_VDI_WRITE;

out:
	free(new);
	free(base);
	return ret;
}

/*
 * Rebase onto another snapshot vdi
 *
 * This makes the current working vdi 'base' a snapshot, and create a new
 * working vdi 'new' based on the snapshot 'base'.  We use this operation when
 * rollbacking to the snapshot or writing data to the snapshot.  Here is an
 * example:
 *
 * [before]
 *                base
 *            o----o----o----x cur
 *
 * [after]
 *                base
 *            o----o----o----o cur
 *                  \
 *                   x new
 * x: working vdi
 * o: snapshot vdi
 */
static int rebase_vdi(const struct vdi_iocb *iocb, uint32_t new_snapid,
		      uint32_t new_vid, uint32_t base_vid, uint32_t cur_vid)
{
	struct sd_inode *new = NULL, *base = xzalloc(sizeof(*base));
	int ret;

	sd_debug("%s: size %" PRIu64 ", vid %" PRIx32 ", base %" PRIx32 ", "
		 "cur %" PRIx32 ", copies %d, block_size_shift %"PRIu8
		 ", snapid %" PRIu32, iocb->name, iocb->size, new_vid,
		 base_vid, cur_vid, iocb->nr_copies, iocb->block_size_shift,
		 new_snapid);

	ret = sd_read_object(vid_to_vdi_oid(base_vid), (char *)base,
			     sizeof(*base), 0);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_BASE_VDI_READ;
		goto out;
	}

	/* TODO: multiple sd_write_object should be performed atomically */

       ret = sd_write_object(vid_to_vdi_oid(cur_vid), (char *)&iocb->time,
                             sizeof(iocb->time),
                             offsetof(struct sd_inode_header, snap_ctime),
			     false);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_VDI_WRITE;
		goto out;
	}

	for (int i = 0; i < ARRAY_SIZE(base->gref); i++) {
		if (base->data_vdi_id[i])
			base->gref[i].count++;
	}
	/* update current working vdi */
	ret = sd_write_object(vid_to_vdi_oid(base_vid), (char *)base->gref,
			      sizeof(base->gref),
			      offsetof(struct sd_inode, gref), false);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_VDI_WRITE;
		goto out;
	}

	/* create a new vdi */
	new = alloc_inode(iocb, new_snapid, new_vid, base->data_vdi_id,
			  base->gref);
	ret = sd_write_object(vid_to_vdi_oid(new_vid), (char *)new,
			      sizeof(*new), 0, true);
	if (ret != SD_RES_SUCCESS)
		ret = SD_RES_VDI_WRITE;

out:
	free(new);
	free(base);
	return ret;
}

/*
 * Return SUCCESS (range of bits set):
 * Iff we get a bitmap range [left, right) that VDI might be set between. if
 * right < left, this means a wrap around case where we should examine the
 * two split ranges, [left, SD_NR_VDIS - 1] and [0, right). 'Right' is the free
 * bit that might be used by newly created VDI.
 *
 * Otherwise:
 * Return NO_VDI (bit not set) or FULL_VDI (bitmap fully set)
 */
static int get_vdi_bitmap_range(const char *name, unsigned long *left,
				unsigned long *right)
{
	*left = sd_hash_vdi(name);

	if (unlikely(!*left))
		*left = 1;	/* 0x000000 should be skipeed */

	*right = find_next_zero_bit(sys->vdi_inuse, SD_NR_VDIS, *left);
	if (*left == *right)
		return SD_RES_NO_VDI;

	if (*right == SD_NR_VDIS) {
		/* Wrap around */
		*right = find_next_zero_bit(sys->vdi_inuse, SD_NR_VDIS, 1);
		if (*right == SD_NR_VDIS)
			return SD_RES_FULL_VDI;
	}
	return SD_RES_SUCCESS;
}

static inline bool vdi_has_tag(const struct vdi_iocb *iocb)
{
	if ((iocb->tag && iocb->tag[0]) || iocb->snapid)
		return true;
	return false;
}

static inline bool vdi_tag_match(const struct vdi_iocb *iocb,
				 const struct sd_inode_header *inode)
{
	const char *tag = iocb->tag;

	if (inode->tag[0] && !strncmp(inode->tag, tag, sizeof(inode->tag)))
		return true;
	if (iocb->snapid == inode->snap_id)
		return true;
	return false;
}

static int fill_vdi_info_range(uint32_t left, uint32_t right,
			       const struct vdi_iocb *iocb,
			       struct vdi_info *info)
{
	struct sd_inode_header inode;
	bool vdi_found = false, acl_denied = false;
	int ret = SD_RES_NO_VDI;
	uint32_t i;
	const char *name = iocb->name;

	for (i = right - 1; i >= left && i; i--) {
		if (!test_bit(i, sys->vdi_inuse) &&
		    !test_bit(i, sys->vdi_deleted))
			continue;

		ret = sd_read_object(vid_to_vdi_oid(i), (char *)&inode,
				     sizeof(inode), 0);
		if (ret != SD_RES_SUCCESS)
			goto out;

		if (!strncmp(inode.name, name, sizeof(inode.name))) {
			sd_debug("%s = %s, %u = %u", iocb->tag,
				 inode.tag, iocb->snapid, inode.snap_id);
			/*
			 * A VDI is only visible to the ACL it was created
			 * with; remember that we skipped one so that we can
			 * tell the caller why nothing matched.
			 */
			if (inode.acl_id != iocb->acl) {
				sd_debug("VDI %" PRIx32 " belongs to ACL %"
					 PRIx32 ", not %" PRIx32, inode.vdi_id,
					 inode.acl_id, iocb->acl);
				acl_denied = true;
				continue;
			}
			if (vdi_has_tag(iocb)) {
				/* Read, delete, clone on snapshots */
				if (!vdi_is_snapshot(&inode)) {
					vdi_found = true;
					info->vid = inode.vdi_id;
					continue;
				}
				if (!vdi_tag_match(iocb, &inode))
					continue;
			} else {
				/*
				 * Rollback & snap create, read, delete on
				 * current working VDI
				 */
				info->snapid = inode.snap_id + 1;
				if (vdi_is_snapshot(&inode)) {
					/* Current working VDI is deleted */
					info->vid = inode.vdi_id;
					break;
				}
			}
			info->create_time = inode.create_time;
			info->vid = inode.vdi_id;
			goto out;
		}
	}
	if (vdi_found)
		ret = SD_RES_NO_TAG;
	else
		ret = acl_denied ? SD_RES_VDI_DENIED : SD_RES_NO_VDI;
out:
	return ret;
}

/* Fill the VDI information from right to left in the bitmap */
static int fill_vdi_info(unsigned long left, unsigned long right,
			 const struct vdi_iocb *iocb, struct vdi_info *info)
{
	bool acl_denied;
	int ret;

	assert(left != right);
	/*
	 * If left == right, fill_vdi_info() shouldn't called by vdi_lookup().
	 * vdi_lookup() must return SD_RES_NO_VDI to its caller.
	 */

	if (left < right)
		return fill_vdi_info_range(left, right, iocb, info);

	if (likely(1 < right))
		ret = fill_vdi_info_range(1, right, iocb, info);
	else
		ret = SD_RES_NO_VDI;

	switch (ret) {
	case SD_RES_NO_VDI:
	case SD_RES_NO_TAG:
	case SD_RES_VDI_DENIED:
		acl_denied = (ret == SD_RES_VDI_DENIED);
		ret = fill_vdi_info_range(left, SD_NR_VDIS, iocb, info);
		if (acl_denied && ret == SD_RES_NO_VDI)
			ret = SD_RES_VDI_DENIED;
		break;
	default:
		break;
	}
	return ret;
}

/* Return SUCCESS if we find targeted VDI specified by iocb and fill info */
int vdi_lookup(const struct vdi_iocb *iocb, struct vdi_info *info)
{
	unsigned long left, right;
	int ret;

	if (!(sys->cinfo.flags & SD_CLUSTER_FLAG_RECYCLE_VID)) {
		ret = get_vdi_bitmap_range(iocb->name, &left, &right);
		info->free_bit = right;
		sd_debug("%s left %lx right %lx, %x", iocb->name, left, right,
			 ret);
		switch (ret) {
		case SD_RES_NO_VDI:
		case SD_RES_FULL_VDI:
			return ret;
		case SD_RES_SUCCESS:
			break;
		}
		return fill_vdi_info(left, right, iocb, info);
	} else {
		/*
		 * Why is the below heavy fill_vdi_info_range() required?
		 *
		 * Older sheepdog didn't have a functionality of recycling VID,
		 * so the above get_vdi_bitmap_range() can detect correct range
		 * of bitmap.
		 *
		 * But newer sheepdog (1.0 <=) recycles VID if a cluster is
		 * formatted with -R option. It can produce situations like
		 * below:
		 *
		 * The first state of VID bitmap:
		 * 0 0 1* 1* 1 0 0 0
		 * 1 is a VID bit of working VDI, 1* is a bit of snapshot.
		 * Assume the above 1 and 1* are used for VDI named "A" and
		 * its snapshots.
		 *
		 * Then, a user tries to create VDI "B". sd_hash_vdi() returns
		 * VID which conflicts with existing bits for A.
		 * 0 0 1* 1* 1 0 0 0
		 *        ^
		 *        |
		 *        sd_hash_vdi() returns VID which conflicts with the
		 *        above bit.
		 *
		 * So B acquires the left most free bit
		 * 0 0 1* 1* 1 1 0 0
		 *             ^
		 *             |
		 *             B acquires this bit.
		 *
		 * Then, the user deletes A and its snapshots. All of the family
		 * members are deleted. The bitmap becomes like below
		 * 0 0 0 0 0 1 0 0
		 *       ^
		 *       |
		 *       B's original VID sd_hash_vdi() calculates.
		 *
		 * Now sheep fails to lookup VID of B, because the VID
		 * calculated by sd_hash_vdi().
		 *
		 * The problem comes from that vdi bitmap is a hashtable with
		 * open addressing. Deleting a member from the table requires
		 * changeing places of the members. It is virtually impossible
		 * in a case of sheepdog (every inode object must be updated).
		 *
		 * This is the reason of the below fill_vdi_info(). Of course it
		 * is ugly and costly. But its cost is equal or less than
		 * "dog vdi list"'s one.
		 */

		info->free_bit = find_next_zero_bit(sys->vdi_inuse,
						    SD_NR_VDIS, 1);
		ret = fill_vdi_info_range(1, SD_NR_VDIS, iocb, info);
		if (ret == SD_RES_NO_VDI && info->vid != 0) {
			/*
			 * handle a case like below:
			 * 1. create A
			 * 2. create snapshots of A
			 * 3. delete A
			 * 4. create A again
			 *
			 * The inode object of A created in 1 shouldn't be
			 * overwritten because snapshots created in 2 depend
			 * on it.
			 */

			if (test_bit(info->vid, sys->vdi_inuse))
				return SD_RES_SUCCESS;
		}

		return ret;
	}
}

static int notify_vdi_add(uint32_t vdi_id, uint32_t nr_copies, uint32_t old_vid,
			  uint8_t copy_policy, uint8_t block_size_shift,
			  uint32_t acl)
{
	int ret;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_NOTIFY_VDI_ADD);
	hdr.vdi_state.old_vid = old_vid;
	hdr.vdi_state.new_vid = vdi_id;
	hdr.vdi_state.acl = acl;
	hdr.vdi_state.copies = nr_copies;
	hdr.vdi_state.set_bitmap = false;
	hdr.vdi_state.copy_policy = copy_policy;
	hdr.vdi_state.block_size_shift = block_size_shift;

	ret = exec_local_req(&hdr, NULL);
	if (ret != SD_RES_SUCCESS)
		sd_err("fail to notify vdi add event(%" PRIx32 ", %d, %" PRIx32
		       ", %"PRIu8 ")", vdi_id, nr_copies,
		       old_vid, block_size_shift);

	return ret;
}

/*
 * This function creates another working vdi with a new name.  The parent of the
 * newly created vdi is iocb->base_vid.
 *
 * There are 2 vdi create operation in SD:
 * 1. fresh create (base_vid == 0)
 * 2. clone create (base_vid != 0)
 *
 * This function expects NO_VDI returned from vdi_lookup().  Fresh create
 * started with id = 1 when there are no snapshot with the same name.  Working
 * VDI always has the highest snapid.
 */
int vdi_create(const struct vdi_iocb *iocb, uint32_t *new_vid)
{
	struct vdi_info info = {};
	int ret;

	ret = vdi_lookup(iocb, &info);
	switch (ret) {
	case SD_RES_SUCCESS:
		return SD_RES_VDI_EXIST;
	case SD_RES_NO_VDI:
		break;
	default:
		sd_err("%s", sd_strerror(ret));
		return ret;
	}

	if (info.snapid == 0)
		info.snapid = 1;
	*new_vid = info.free_bit;
	ret = notify_vdi_add(*new_vid, iocb->nr_copies,
			     iocb->base_vid == 0 ? info.vid : iocb->base_vid,
			     iocb->copy_policy, iocb->block_size_shift,
			     iocb->acl);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (iocb->base_vid == 0)
		return create_vdi(iocb, info.snapid, *new_vid);
	else
		return clone_vdi(iocb, info.snapid, *new_vid, iocb->base_vid);
}

/*
 * This function makes the current working vdi a snapshot, and create a new
 * working vdi with the same name.  The parent of the newly created vdi is
 * iocb->base_vid.
 *
 * There are 2 snapshot create operation in SD:
 * 1. snapshot create (base_vid == current_vid)
 * 2. rollback create (base_vid != current_vid)
 *
 * This function expects SUCCESS returned from vdi_lookup().  Both rollback and
 * snap create started with current working VDI's snap_id + 1. Working VDI
 * always has the highest snapid.
 */
int vdi_snapshot(const struct vdi_iocb *iocb, uint32_t *new_vid)
{
	struct vdi_info info = {};
	int ret;

	ret = vdi_lookup(iocb, &info);
	if (ret != SD_RES_SUCCESS) {
		sd_err("%s", sd_strerror(ret));
		return ret;
	}

	sd_assert(info.snapid > 0);
	*new_vid = info.free_bit;
	ret = notify_vdi_add(*new_vid, iocb->nr_copies, info.vid,
			     iocb->copy_policy, iocb->block_size_shift,
			     iocb->acl);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (iocb->base_vid == info.vid)
		return snapshot_vdi(iocb, info.snapid, *new_vid,
				    iocb->base_vid);
	else
		return rebase_vdi(iocb, info.snapid, *new_vid, iocb->base_vid,
				  info.vid);
}

int read_vdis(char *data, int len, unsigned int *rsp_len)
{
	if (len != sizeof(sys->vdi_inuse))
		return SD_RES_INVALID_PARMS;

	memcpy(data, sys->vdi_inuse, sizeof(sys->vdi_inuse));
	*rsp_len = sizeof(sys->vdi_inuse);

	return SD_RES_SUCCESS;
}

int read_del_vdis(char *data, int len, unsigned int *rsp_len)
{
	if (len != sizeof(sys->vdi_deleted))
		return SD_RES_INVALID_PARMS;

	memcpy(data, sys->vdi_deleted, sizeof(sys->vdi_deleted));
	*rsp_len = sizeof(sys->vdi_deleted);

	return SD_RES_SUCCESS;
}

struct deletion_work {
	struct work work;
	uint32_t target_vid;
	bool succeed;
	int finish_fd;		/* eventfd for notifying finish */
};

static int notify_vdi_deletion(uint32_t vdi_id)
{
	struct sd_req hdr;
	int ret;

	sd_init_req(&hdr, SD_OP_NOTIFY_VDI_DEL);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(vdi_id);

	ret = exec_local_req(&hdr, &vdi_id);
	if (ret != SD_RES_SUCCESS)
		sd_err("fail to notify vdi deletion(%" PRIx32 "), %d", vdi_id,
		       ret);

	return ret;
}

struct delete_arg {
	const struct sd_inode *inode;
	uint32_t *nr_deleted;
};

static void delete_cb(struct sd_index *idx, void *arg, int ignore)
{
	struct delete_arg *darg = (struct delete_arg *)arg;
	uint64_t oid;
	int ret;

	if (idx->vdi_id) {
		oid = vid_to_data_oid(idx->vdi_id, idx->idx);
		if (idx->vdi_id != darg->inode->header.vdi_id)
			sd_debug("object %016" PRIx64 " is base's data, would"
				 " not be deleted.", oid);
		else {
			ret = sd_remove_object(oid);
			if (ret != SD_RES_SUCCESS)
				sd_err("remove object %016" PRIx64 " fail, %d",
				       oid, ret);
			(*(darg->nr_deleted))++;
		}
	}
}

static void delete_vdi_work(struct work *work)
{
	struct deletion_work *dw =
		container_of(work, struct deletion_work, work);
	int ret = 0;
	uint32_t i, nr_deleted, nr_objs;
	struct sd_inode *inode = NULL;
	uint32_t vdi_id = dw->target_vid;

	inode = malloc(sizeof(*inode));
	if (!inode) {
		sd_err("failed to allocate memory");
		dw->succeed = false;
		return;
	}

	ret = sd_read_object(vid_to_vdi_oid(vdi_id),
			     (void *)inode, sizeof(*inode), 0);

	if (ret != SD_RES_SUCCESS) {
		sd_err("cannot find VDI object");
		dw->succeed = false;
		goto out;
	}

	if (inode->header.vdi_size == 0 && vdi_is_deleted(inode))
		goto out;

	if (!sd_store_policy_is_hyper(&inode->header)) {
		nr_objs = count_data_objs(&inode->header);
		for (nr_deleted = 0, i = 0; i < nr_objs; i++) {
			uint32_t vid = sd_inode_get_vid(inode, i);

			if (vid) {
				sd_err("vid: %"PRIx32" still has objects", vid);
				dw->succeed = false;
				goto out;
			}
		}
	} else {
		/*
		 * todo: generational reference counting is not supported by
		 * hypervolume yet
		 */
		struct delete_arg arg = {inode, &nr_deleted};
		sd_inode_index_walk(inode, delete_cb, &arg);
	}

	if (vdi_is_deleted(inode))
		goto out;

	inode->header.vdi_size = 0;
	memset(inode->header.name, 0, sizeof(inode->header.name));
	memset((char *)inode + SD_INODE_HEADER_SIZE, 0,
	       SD_INODE_SIZE - SD_INODE_HEADER_SIZE);

	sd_write_object(vid_to_vdi_oid(vdi_id), (void *)inode,
			sizeof(*inode), 0, false);

	if (nr_deleted)
		notify_vdi_deletion(vdi_id);
out:
	free(inode);
	dw->succeed = true;
}

static void delete_vdi_done(struct work *work)
{
	struct deletion_work *dw =
		container_of(work, struct deletion_work, work);

	eventfd_xwrite(dw->finish_fd, 1);
	if (!dw->succeed)
		sd_err("deleting vdi: %x failed", dw->target_vid);
	/* the deletion work is completed */
	free(dw);
}

static int start_deletion(struct request *req, uint32_t vid)
{
	struct deletion_work *dw = NULL;
	struct sd_rsp *rsp = &req->rp;
	int ret = SD_RES_SUCCESS, finish_fd;

	dw = xzalloc(sizeof(*dw));
	dw->target_vid = vid;
	finish_fd = dw->finish_fd = eventfd(0, 0);
	if (dw->finish_fd < 0) {
		sd_err("cannot create an eventfd for notifying finish of"
		       " deletion info: %m");
		goto out;
	}

	dw->work.fn = delete_vdi_work;
	dw->work.done = delete_vdi_done;

	queue_work(sys->deletion_wqueue, &dw->work);

	/*
	 * the event fd is written by delete_vdi_done(), when all reference
	 * counters are decremented
	 */
	eventfd_xread(finish_fd);
	close(finish_fd);

	rsp->vdi.vdi_id = vid;

	return ret;
out:
	free(dw);

	return ret;
}

int vdi_delete(const struct vdi_iocb *iocb, struct request *req)
{
	struct vdi_info info;
	int ret;

	ret = vdi_lookup(iocb, &info);
	if (ret != SD_RES_SUCCESS)
		goto out;

	ret = start_deletion(req, info.vid);
out:
	return ret;
}

void vdi_mark_deleted(uint32_t vid)
{
	struct vdi_state_entry *entry;

	sd_write_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);
	if (!entry) {
		sd_err("VID: %"PRIx32" not found", vid);
		goto out;
	}

	entry->deleted = true;
out:
	sd_rw_unlock(&vdi_state_lock);
}

/* Calculate a vdi attribute id from sheepdog_vdi_attr. */
static uint32_t hash_vdi_attr(const struct sheepdog_vdi_attr *attr)
{
	uint64_t hval;

	/* We cannot use sd_hash for backward compatibility. */
	hval = fnv_64a_buf(attr->name, sizeof(attr->name), FNV1A_64_INIT);
	hval = fnv_64a_buf(attr->tag, sizeof(attr->tag), hval);
	hval = fnv_64a_buf(&attr->snap_id, sizeof(attr->snap_id), hval);
	hval = fnv_64a_buf(attr->key, sizeof(attr->key), hval);

	return (uint32_t)(hval & ((UINT64_C(1) << VDI_SPACE_SHIFT) - 1));
}

int get_vdi_attr(struct sheepdog_vdi_attr *vattr, int data_len,
		 uint32_t vid, uint32_t *attrid, uint64_t create_time,
		 bool wr, bool excl, bool delete)
{
	struct sheepdog_vdi_attr tmp_attr;
	uint64_t oid;
	uint32_t end;
	int ret = SD_RES_NO_OBJ;

	vattr->ctime = create_time;

	*attrid = hash_vdi_attr(vattr);

	end = *attrid - 1;
	while (*attrid != end) {
		oid = vid_to_attr_oid(vid, *attrid);
		if (excl || !wr)
			ret = sd_read_object(oid, (char *)&tmp_attr,
					sizeof(tmp_attr), 0);

		if (ret == SD_RES_NO_OBJ && wr) {
			ret = sd_write_object(oid, (char *)vattr, data_len, 0,
					      true);
			if (ret)
				ret = SD_RES_EIO;
			else
				ret = SD_RES_SUCCESS;
			goto out;
		}

		if (ret != SD_RES_SUCCESS)
			goto out;

		/* compare attribute header */
		if (strcmp(tmp_attr.name, vattr->name) == 0 &&
		    strcmp(tmp_attr.tag, vattr->tag) == 0 &&
		    tmp_attr.snap_id == vattr->snap_id &&
		    strcmp(tmp_attr.key, vattr->key) == 0) {
			if (excl)
				ret = SD_RES_VDI_EXIST;
			else if (delete) {
				ret = sd_write_object(oid, (char *)"", 1,
				offsetof(struct sheepdog_vdi_attr, name),
						      false);
				if (ret)
					ret = SD_RES_EIO;
				else
					ret = SD_RES_SUCCESS;
			} else if (wr) {
				ret = sd_write_object(oid, (char *)vattr,
						      SD_ATTR_OBJ_SIZE, 0,
						      false);

				if (ret)
					ret = SD_RES_EIO;
				else
					ret = SD_RES_SUCCESS;
			} else
				ret = SD_RES_SUCCESS;
			goto out;
		}

		(*attrid)++;
	}

	sd_debug("there is no space for new VDIs");
	ret = SD_RES_FULL_VDI;
out:
	return ret;
}

static void clean_family(struct vdi_family_member *member)
{
	struct vdi_family_member *child;

	list_for_each_entry(child, &member->child_list_head, child_list_node) {
		clean_family(child);
	}

	if (list_linked(&member->child_list_node))
		list_del(&member->child_list_node);

	if (!list_linked(&member->roots_list))
		free(member);
}

void clean_vdi_state(void)
{
	struct vdi_family_member *member, *tmp;

	sd_write_lock(&vdi_state_lock);
	rb_destroy(&vdi_state_root, struct vdi_state_entry, node);
	INIT_RB_ROOT(&vdi_state_root);
	sd_rw_unlock(&vdi_state_lock);

	sd_mutex_lock(&vdi_family_mutex);

	list_for_each_entry_safe(member, tmp, &vdi_family_roots, roots_list) {
		clean_family(member);
		list_del(&member->roots_list);
		free(member);
	}

	sd_mutex_unlock(&vdi_family_mutex);
}

int sd_delete_vdi(const char *name)
{
	struct sd_req hdr;
	char data[SD_MAX_VDI_LEN] = {0};
	int ret;

	sd_init_req(&hdr, SD_OP_DEL_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(data);
	pstrcpy(data, SD_MAX_VDI_LEN, name);

	ret = exec_local_req(&hdr, data);
	if (ret != SD_RES_SUCCESS)
		sd_err("Failed to delete vdi %s %s", name, sd_strerror(ret));

	return ret;
}

int sd_lookup_vdi(const char *name, uint32_t *vid)
{
	int ret;
	struct vdi_info info = {};
	struct vdi_iocb iocb = {
		.name = name,
		.data_len = strlen(name),
	};

	ret = vdi_lookup(&iocb, &info);
	switch (ret) {
	case SD_RES_SUCCESS:
		*vid = info.vid;
		break;
	case SD_RES_NO_VDI:
		break;
	default:
		sd_err("Failed to lookup name %s, %s", name, sd_strerror(ret));
	}

	return ret;
}

int sd_create_hyper_volume(const char *name, uint32_t *vdi_id)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char buf[SD_MAX_VDI_LEN] = {};
	int ret;

	pstrcpy(buf, SD_MAX_VDI_LEN, name);

	sd_init_req(&hdr, SD_OP_NEW_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = SD_MAX_VDI_LEN;

	hdr.vdi.vdi_size = SD_MAX_VDI_SIZE;
	hdr.vdi.copies = sys->cinfo.nr_copies;
	hdr.vdi.copy_policy = sys->cinfo.copy_policy;
	hdr.vdi.store_policy = SD_HYPER_STORE_POLICY;
	/* XXX Cannot use both features, Hypervolume and Change object size */
	if (sys->cinfo.block_size_shift != SD_DEFAULT_BLOCK_SIZE_SHIFT) {
		hdr.vdi.block_size_shift = SD_DEFAULT_BLOCK_SIZE_SHIFT;
		sd_warn("Cluster default object size is not"
			" SD_DATA_OBJ_SIZE(%d)."
			"Set VDI object size %d and create HyperVolume",
			SD_DEFAULT_BLOCK_SIZE_SHIFT,
			SD_DEFAULT_BLOCK_SIZE_SHIFT);
	}

	ret = exec_local_req(&hdr, buf);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to create VDI %s: %s", name, sd_strerror(ret));
		goto out;
	}

	if (vdi_id)
		*vdi_id = rsp->vdi.vdi_id;
out:
	return ret;
}

struct vdi_state_checkpoint {
	int epoch, nr_vs;
	struct vdi_state *vs;

	/* one reference per node which is going to collect this checkpoint */
	int refcnt;

	struct list_node list;
};

static LIST_HEAD(vdi_state_checkpoint_list);

main_fn void create_vdi_state_checkpoint(int epoch)
{
	/*
	 * take a checkpoint of current vdi state and associate it with
	 * the given epoch
	 */
	struct vdi_state_checkpoint *checkpoint;

	list_for_each_entry(checkpoint, &vdi_state_checkpoint_list, list) {
		if (checkpoint->epoch == epoch) {
			/*
			 * More than one node can join at the same epoch, and
			 * each of them frees this checkpoint once it collected
			 * its VDI state.  Keep it until the last one is done,
			 * otherwise the others find it gone and give up.
			 */
			checkpoint->refcnt++;
			sd_debug("checkpoint of epoch %d is shared by %d nodes",
				 epoch, checkpoint->refcnt);
			return;
		}

	}

	checkpoint = xzalloc(sizeof(*checkpoint));
	checkpoint->epoch = epoch;
	checkpoint->refcnt = 1;
	checkpoint->vs = fill_vdi_state_list_with_alloc(&checkpoint->nr_vs);
	INIT_LIST_NODE(&checkpoint->list);
	list_add_tail(&checkpoint->list, &vdi_state_checkpoint_list);

	sd_debug("creating a checkpoint of vdi state at epoch %d succeed",
		 epoch);
	sd_debug("a number of vdi state: %d", checkpoint->nr_vs);
}

main_fn int get_vdi_state_checkpoint(int epoch, uint32_t vid, void *data)
{
	struct vdi_state_checkpoint *checkpoint;
	struct vdi_state *vs;

	list_for_each_entry(checkpoint, &vdi_state_checkpoint_list, list) {
		if (checkpoint->epoch == epoch) {
			for (int i = 0; i < checkpoint->nr_vs; i++) {
				if (checkpoint->vs[i].vid == vid) {
					vs = &checkpoint->vs[i];
					goto found;
				}
			}

			sd_info("this node doesn't have a required entry of VID:"
				" %"PRIx32" at epoch %d", vid, epoch);
			return SD_RES_NO_CHECKPOINT_ENTRY;
		}
	}

	sd_info("get request for not prepared vdi state checkpoint, epoch: %d",
		epoch);
	return SD_RES_AGAIN;

found:
	memcpy(data, vs, sizeof(*vs));
	return SD_RES_SUCCESS;
}

main_fn void free_vdi_state_checkpoint(int epoch)
{
	struct vdi_state_checkpoint *checkpoint;

	list_for_each_entry(checkpoint, &vdi_state_checkpoint_list, list) {
		if (checkpoint->epoch == epoch) {
			if (--checkpoint->refcnt > 0) {
				sd_debug("checkpoint of epoch %d is still needed"
					 " by %d nodes", epoch,
					 checkpoint->refcnt);
				return;
			}

			list_del(&checkpoint->list);
			free(checkpoint->vs);
			free(checkpoint);

			return;
		}
	}

	/*
	 * A node only takes a checkpoint when it sees somebody else join, so a
	 * node which joined together with the requester never had one.  Losing
	 * a checkpoint we do not have is nothing to die for.
	 */
	sd_info("no vdi state checkpoint of epoch %d to free", epoch);
}

static int clean_matched_obj(uint64_t oid, const char *path,
			     uint32_t epoch, uint8_t ec_index,
			     struct vnode_info *vinfo, void *arg)
{
	uint32_t vid = oid_to_vid(*(uint64_t *)arg);
	int ret = SD_RES_SUCCESS;

	if (oid_to_vid(oid) == vid) {
		sd_info("removing object %016"PRIx64" (path: %s), it means the"
			" object is leaked", oid, path);
		ret = unlink(path);
		if (ret) {
			sd_err("failed to unlink %s", path);
			ret = SD_RES_EIO;
		}
	}

	return ret;
}

static main_fn void do_vid_gc(struct vdi_family_member *member)
{
	struct vdi_state_entry *entry = member->entry;
	uint32_t vid = entry->vid;
	uint64_t oid = vid_to_vdi_oid(vid);
	struct vdi_family_member *child;

	rb_erase(&entry->node, &vdi_state_root);
	free(entry);

	list_for_each_entry(child, &member->child_list_head, child_list_node) {
		do_vid_gc(child);
	}

	if (list_linked(&member->roots_list))
		list_del(&member->roots_list);

	free(member);

	if (sd_store && sd_store->exist(oid, -1)) {
		sd_store->remove_object(oid, -1);
		for_each_object_in_wd(clean_matched_obj, false, &oid);
	}

	atomic_clear_bit(vid, sys->vdi_inuse);
	atomic_clear_bit(vid, sys->vdi_deleted);
}

main_fn void run_vid_gc(uint32_t vid)
{
	struct vdi_state_entry *entry;
	struct vdi_family_member *member, *root;

	sd_write_lock(&vdi_state_lock);
	sd_mutex_lock(&vdi_family_mutex);
	entry = vdi_state_search(&vdi_state_root, vid);
	if (!entry) {
		sd_alert("vid %"PRIx32" doesn't have its entry", vid);
		goto out;
	}

	member = entry->family_member;
	root = lookup_root(member);

	if (is_all_members_deleted(root)) {
		sd_info("all members of the family (root: %"PRIx32
			") are deleted", root->vid);
		do_vid_gc(root);
	} else
		sd_info("not all members of the family (root: %"PRIx32
			") are deleted", root->vid);

out:
	sd_mutex_unlock(&vdi_family_mutex);
	sd_rw_unlock(&vdi_state_lock);

}
