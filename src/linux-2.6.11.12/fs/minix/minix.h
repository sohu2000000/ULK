#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/minix_fs.h>

/*
 * change the define below to 0 if you want names > info->s_namelen chars to be
 * truncated. Else they will be disallowed (ENAMETOOLONG).
 */
#define NO_TRUNCATE 1

#define INODE_VERSION(inode)	minix_sb(inode->i_sb)->s_version

#define MINIX_V1		0x0001		/* original minix fs */
#define MINIX_V2		0x0002		/* minix V2 fs */

/*
 * minix fs inode data in memory
 */
/* �ڴ��е�MINIX�ڵ� */
struct minix_inode_info {
	union {
		/* �ļ���ռ�õ������߼�������飬���2.0�汾 */
		__u16 i1_data[16];
		/* �ļ���ռ�õ������߼�������飬����0-6��ֱ�ӿ�ţ�7��һ�μ�ӿ飬8�Ƕ��μ�ӿ飬9�����μ�ӿ� */
		__u32 i2_data[16];
	} u;
	/* ��Ƕ��VFS�ڵ� */
	struct inode vfs_inode;
};

/*
 * minix super-block data in memory
 */
/* MINIX�ļ�ϵͳ���ڴ��еĳ�����ṹ */
struct minix_sb_info {
	/* i�ڵ��� */
	unsigned long s_ninodes;
	/* �߼����� */
	unsigned long s_nzones;
	/* i�ڵ�λͼ��ռ���� */
	unsigned long s_imap_blocks;
	/* �߼���λͼ��ռ���� */
	unsigned long s_zmap_blocks;
	/* �������е�һ���߼���� */
	unsigned long s_firstdatazone;
	/* log2(���̿���/�߼���) */
	unsigned long s_log_zone_size;
	/* �����ļ����ȣ����ֽ�Ϊ��λ */
	unsigned long s_max_size;
	/* Ŀ¼��ĳ��� */
	int s_dirsize;
	/* Ŀ¼�����ļ����ĳ��� */
	int s_namelen;
	/* ���������� */
	int s_link_max;
	/* i�ڵ�λͼ������ */
	struct buffer_head ** s_imap;
	/* �߼���λͼ������ */
	struct buffer_head ** s_zmap;
	/* �����黺���� */
	struct buffer_head * s_sbh;
	/* ָ������ϳ������ָ�� */
	struct minix_super_block * s_ms;
	unsigned short s_mount_state;
	/* �ļ�ϵͳ�汾 */
	unsigned short s_version;
};

extern struct minix_inode * minix_V1_raw_inode(struct super_block *, ino_t, struct buffer_head **);
extern struct minix2_inode * minix_V2_raw_inode(struct super_block *, ino_t, struct buffer_head **);
extern struct inode * minix_new_inode(const struct inode * dir, int * error);
extern void minix_free_inode(struct inode * inode);
extern unsigned long minix_count_free_inodes(struct minix_sb_info *sbi);
extern int minix_new_block(struct inode * inode);
extern void minix_free_block(struct inode * inode, int block);
extern unsigned long minix_count_free_blocks(struct minix_sb_info *sbi);

extern int minix_getattr(struct vfsmount *, struct dentry *, struct kstat *);

extern void V2_minix_truncate(struct inode *);
extern void V1_minix_truncate(struct inode *);
extern void V2_minix_truncate(struct inode *);
extern void minix_truncate(struct inode *);
extern int minix_sync_inode(struct inode *);
extern void minix_set_inode(struct inode *, dev_t);
extern int V1_minix_get_block(struct inode *, long, struct buffer_head *, int);
extern int V2_minix_get_block(struct inode *, long, struct buffer_head *, int);
extern unsigned V1_minix_blocks(loff_t);
extern unsigned V2_minix_blocks(loff_t);

extern struct minix_dir_entry *minix_find_entry(struct dentry*, struct page**);
extern int minix_add_link(struct dentry*, struct inode*);
extern int minix_delete_entry(struct minix_dir_entry*, struct page*);
extern int minix_make_empty(struct inode*, struct inode*);
extern int minix_empty_dir(struct inode*);
extern void minix_set_link(struct minix_dir_entry*, struct page*, struct inode*);
extern struct minix_dir_entry *minix_dotdot(struct inode*, struct page**);
extern ino_t minix_inode_by_name(struct dentry*);

extern int minix_sync_file(struct file *, struct dentry *, int);

extern struct inode_operations minix_file_inode_operations;
extern struct inode_operations minix_dir_inode_operations;
extern struct file_operations minix_file_operations;
extern struct file_operations minix_dir_operations;
extern struct dentry_operations minix_dentry_operations;

static inline struct minix_sb_info *minix_sb(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct minix_inode_info *minix_i(struct inode *inode)
{
	return list_entry(inode, struct minix_inode_info, vfs_inode);
}
