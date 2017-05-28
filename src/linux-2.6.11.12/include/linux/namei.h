#ifndef _LINUX_NAMEI_H
#define _LINUX_NAMEI_H

#include <linux/linkage.h>

struct vfsmount;

struct open_intent {
	int	flags;
	int	create_mode;
};

enum { MAX_NESTED_LINKS = 5 };

/**
 * ·�����ҵĽ��
 */
struct nameidata {
	/**
	 * ���ҵ���Ŀ¼����
	 */
	struct dentry	*dentry;
	/**
	 * �Ѿ���װ���ļ�ϵͳ����
	 */
	struct vfsmount *mnt;
	/**
	 * ·���������һ����������ָ��LOOKUP_PARENTʱʹ�á�
	 */
	struct qstr	last;
	/**
	 * ���ұ�־��
	 */
	unsigned int	flags;
	/**
	 * ·�������һ�����������͡���LAST_NORM
	 */
	int		last_type;
	/**
	 * �������Ӳ��ҵ�Ƕ����ȡ�
	 */
	unsigned	depth;
	/**
	 * Ƕ�׹���·�������顣
	 */
	char *saved_names[MAX_NESTED_LINKS + 1];

	/* Intent data */
	/**
	 * ָ����η����ļ���
	 */
	union {
		struct open_intent open;
	} intent;
};

/*
 * Type of the last component on LOOKUP_PARENT
 */
/**
 * LAST_NORM:	���һ����������ͨ�ļ���
 * LAST_ROOT:	���һ��������"/"
 * LAST_DOT:	���һ��������"."
 * LAST_DOTDOT:	���һ��������".."
 * LAST_BIND:	���һ�����������ӵ������ļ�ϵͳ�ķ�������
 */
enum {LAST_NORM, LAST_ROOT, LAST_DOT, LAST_DOTDOT, LAST_BIND};

/*
 * The bitmask for a lookup event:
 *  - follow links at the end
 *  - require a directory
 *  - ending slashes ok even for nonexistent files
 *  - internal "there are more path compnents" flag
 *  - locked when lookup done with dcache_lock held
 */
/**
 * ������һ�������Ƿ������ӣ����������
 */
#define LOOKUP_FOLLOW		 1
/**
 * ���һ������������Ŀ¼��
 */
#define LOOKUP_DIRECTORY	 2
/**
 * ��·�����л����ļ���Ҫ��顣
 */
#define LOOKUP_CONTINUE		 4
/**
 * �������һ���������ڵ�Ŀ¼
 */
#define LOOKUP_PARENT		16
/**
 * ������ģ���Ŀ¼(x86��ϵ�ṹ��û��)
 */
#define LOOKUP_NOALT		32
/*
 * Intent data
 */
/**
 * ��ͼ��һ���ļ�
 */
#define LOOKUP_OPEN		(0x0100)
/**
 * ��ͼ����һ���ļ�
 */
#define LOOKUP_CREATE		(0x0200)
/**
 * ��ͼΪһ���ļ�����û���Ȩ�ޡ�
 */
#define LOOKUP_ACCESS		(0x0400)

extern int FASTCALL(__user_walk(const char __user *, unsigned, struct nameidata *));
#define user_path_walk(name,nd) \
	__user_walk(name, LOOKUP_FOLLOW, nd)
#define user_path_walk_link(name,nd) \
	__user_walk(name, 0, nd)
extern int FASTCALL(path_lookup(const char *, unsigned, struct nameidata *));
extern int FASTCALL(path_walk(const char *, struct nameidata *));
extern int FASTCALL(link_path_walk(const char *, struct nameidata *));
extern void path_release(struct nameidata *);
extern void path_release_on_umount(struct nameidata *);

extern struct dentry * lookup_one_len(const char *, struct dentry *, int);
extern struct dentry * lookup_hash(struct qstr *, struct dentry *);

extern int follow_down(struct vfsmount **, struct dentry **);
extern int follow_up(struct vfsmount **, struct dentry **);

extern struct dentry *lock_rename(struct dentry *, struct dentry *);
extern void unlock_rename(struct dentry *, struct dentry *);

static inline void nd_set_link(struct nameidata *nd, char *path)
{
	nd->saved_names[nd->depth] = path;
}

static inline char *nd_get_link(struct nameidata *nd)
{
	return nd->saved_names[nd->depth];
}

#endif /* _LINUX_NAMEI_H */
