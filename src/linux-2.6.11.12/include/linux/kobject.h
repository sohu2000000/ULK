/*
 * kobject.h - generic kernel object infrastructure.
 *
 * Copyright (c) 2002-2003	Patrick Mochel
 * Copyright (c) 2002-2003	Open Source Development Labs
 *
 * This file is released under the GPLv2.
 *
 * 
 * Please read Documentation/kobject.txt before using the kobject
 * interface, ESPECIALLY the parts about reference counts and object
 * destructors. 
 */

#ifndef _KOBJECT_H_
#define _KOBJECT_H_

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include <linux/rwsem.h>
#include <linux/kref.h>
#include <linux/kobject_uevent.h>
#include <linux/kernel.h>
#include <asm/atomic.h>

#define KOBJ_NAME_LEN	20

/* counter to tag the hotplug event, read only except for the kobject core */
extern u64 hotplug_seqnum;

/**
 * �豸��������ģ�͵ĺ������ݽṹ����Ӧ��sysfs�ļ�ϵͳ��ÿһ��Ŀ¼��
 * ��ͨ�����ŵ��豸���������һ���������С����͵����������ߡ��豸������������������
 */
struct kobject {
	/**
	 * ָ���������ơ�
	 */
	char			* k_name;
	/**
	 * ����������Ʋ�����20���ַ����ʹ������
	 */
	char			name[KOBJ_NAME_LEN];
	/**
	 * ���������ü�����
	 */
	struct kref		kref;
	/**
	 * ���ڽ�kobject����ĳ������
	 */
	struct list_head	entry;
	/**
	 * ָ��kobject
	 */
	struct kobject		* parent;
	/**
	 * ָ�������kset,kset��ͬ���͵�kobject�ṹ��һ�������塣
	 */
	struct kset		* kset;
	/**
	 * ָ��kobject��������������
	 */
	struct kobj_type	* ktype;
	/**
	 * ָ����kobject��Ӧ��sysfs�ļ���dentry���ݽṹ��
	 */
	struct dentry		* dentry;
};

extern int kobject_set_name(struct kobject *, const char *, ...)
	__attribute__((format(printf,2,3)));

static inline char * kobject_name(struct kobject * kobj)
{
	return kobj->k_name;
}

extern void kobject_init(struct kobject *);
extern void kobject_cleanup(struct kobject *);

extern int kobject_add(struct kobject *);
extern void kobject_del(struct kobject *);

extern int kobject_rename(struct kobject *, char *new_name);

extern int kobject_register(struct kobject *);
extern void kobject_unregister(struct kobject *);

extern struct kobject * kobject_get(struct kobject *);
extern void kobject_put(struct kobject *);

extern char * kobject_get_path(struct kobject *, int);

/**
 * ��������kobject����Ľṹ���͡������ϣ����������ǰ���kobject������������
 */
struct kobj_type {
	/**
	 * kobject���͵�release������
	 */
	void (*release)(struct kobject *);
	/**
	 * ʵ�ֶ������Եķ�����sysfs�����б�
	 */
	struct sysfs_ops	* sysfs_ops;
	/**
	 * ������kobjectʱ������ö����Ĭ�����ԡ�sysfs�ļ�ϵͳ��ȱʡ�����б�
	 */
	struct attribute	** default_attrs;
};


/**
 *	kset - a set of kobjects of a specific type, belonging
 *	to a specific subsystem.
 *
 *	All kobjects of a kset should be embedded in an identical 
 *	type. This type may have a descriptor, which the kset points
 *	to. This allows there to exist sets of objects of the same
 *	type in different subsystems.
 *
 *	A subsystem does not have to be a list of only one type 
 *	of object; multiple ksets can belong to one subsystem. All 
 *	ksets of a subsystem share the subsystem's lock.
 *
 *      Each kset can support hotplugging; if it does, it will be given
 *      the opportunity to filter out specific kobjects from being
 *      reported, as well as to add its own "data" elements to the
 *      environment being passed to the hotplug helper.
 */
/**
 * �����Ȳ岦�¼��Ľṹ����kset��hotplug_opsָ��ýṹ��
 * ���kset������һ��ָ����kobject������sysfs�ֲ�ṹ�н���������ֱ���ҵ�һ��������kset��kobjectΪֹ��Ȼ��ʹ�����kset���Ȳ岦������
 */
struct kset_hotplug_ops {
	/**
	 * ���ۺ�ʱ�����ں�ҪΪָ����kobject�����¼�ʱ����Ҫ����filter���������filter��������0�����������¼���
	 * ��ˣ��ú�����ksetһ�����ᣬ���ھ����Ƿ����û��ռ䴫��ָ�����¼���
	 * ʹ�ô˺�����һ�������ǿ��豸��ϵͳ����block_hotplug_filter�У�ֻΪkobject�������̺ͷ����¼���������Ϊ�������kobject�����¼���
	 */
	int (*filter)(struct kset *kset, struct kobject *kobj);
	/**
	 * �ڵ����û��ռ���Ȳ岦����ʱ�������ϵͳ�����ֽ���ΪΨһ�Ĳ������ݸ�����
	 * name���������ṩ�����֡���������һ���ʺϴ��ݸ��û��ռ���ַ�����
	 */
	char *(*name)(struct kset *kset, struct kobject *kobj);
	/**
	 * �κ��Ȳ岦�ű�����Ҫ֪������Ϣ��ͨ�������������ݡ����һ��hotplug�������ڵ��ýű�ǰ���ṩ��ӻ��������Ļ��ᡣ
	 */
	int (*hotplug)(struct kset *kset, struct kobject *kobj, char **envp,
			int num_envp, char *buffer, int buffer_size);
};

/**
 * Ƕ����ͬ���ͽṹ��kobject���ϡ�
 * ������һ��kobject����ʱ��ͨ����Ҫ�����Ǽ��뵽kset�С�
 */
struct kset{
	/**
	 * ������ϵͳ��
	 */
	struct subsystem	* subsys;
	/**
	 * ��������kobjec�����͡�
	 */
	struct kobj_type	* ktype;
	/**
	 * ��һ��kobject�ڵ㡣
	 */
	struct list_head	list;
	/**
	 * Ƕ���kobject
	 */
	struct kobject		kobj;
	/**
	 * ���ڴ���kobject�ṹ�Ĺ��˺��Ȳ岦�����Ļص�������
	 */
	struct kset_hotplug_ops	* hotplug_ops;
};


extern void kset_init(struct kset * k);
extern int kset_add(struct kset * k);
extern int kset_register(struct kset * k);
extern void kset_unregister(struct kset * k);

static inline struct kset * to_kset(struct kobject * kobj)
{
	return kobj ? container_of(kobj,struct kset,kobj) : NULL;
}

/*
 * ����kset�����ü�����ֻ��򵥵ĵ�����Ƕkobject�ṹ�е�kobject_get
 */
static inline struct kset * kset_get(struct kset * k)
{
	return k ? to_kset(kobject_get(&k->kobj)) : NULL;
}

/*
 * ����kset�����ü�����ֻ��򵥵ĵ�����Ƕkobject�ṹ�е�kobject_put
 */
static inline void kset_put(struct kset * k)
{
	kobject_put(&k->kobj);
}

static inline struct kobj_type * get_ktype(struct kobject * k)
{
	if (k->kset && k->kset->ktype)
		return k->kset->ktype;
	else 
		return k->ktype;
}

extern struct kobject * kset_find_obj(struct kset *, const char *);


/**
 * Use this when initializing an embedded kset with no other 
 * fields to initialize.
 */
#define set_kset_name(str)	.kset = { .kobj = { .name = str } }



/**
 * ��ϵͳ��ͨ����ʾ��sysfs�ֲ�ṹ�еĶ��㡣
 * ����block_subsys��devices_subsys�Լ��������ߵ���ϵͳ����Ӧ��sys/block��sys/devices��Ŀ¼��
 */
struct subsystem {
	/**
	 * �²���󼯺ϡ�
	 */
	struct kset		kset;
	/**
	 * ������ϵͳ���õĶ�д�ź�����
	 */
	struct rw_semaphore	rwsem;
};

/**
 * ����һ����ϵͳ��
 */
#define decl_subsys(_name,_type,_hotplug_ops) \
struct subsystem _name##_subsys = { \
	.kset = { \
		.kobj = { .name = __stringify(_name) }, \
		.ktype = _type, \
		.hotplug_ops =_hotplug_ops, \
	} \
}
#define decl_subsys_name(_varname,_name,_type,_hotplug_ops) \
struct subsystem _varname##_subsys = { \
	.kset = { \
		.kobj = { .name = __stringify(_name) }, \
		.ktype = _type, \
		.hotplug_ops =_hotplug_ops, \
	} \
}

/* The global /sys/kernel/ subsystem for people to chain off of */
extern struct subsystem kernel_subsys;

/**
 * Helpers for setting the kset of registered objects.
 * Often, a registered object belongs to a kset embedded in a 
 * subsystem. These do no magic, just make the resulting code
 * easier to follow. 
 */

/**
 *	kobj_set_kset_s(obj,subsys) - set kset for embedded kobject.
 *	@obj:		ptr to some object type.
 *	@subsys:	a subsystem object (not a ptr).
 *
 *	Can be used for any object type with an embedded ->kobj.
 */

#define kobj_set_kset_s(obj,subsys) \
	(obj)->kobj.kset = &(subsys).kset

/**
 *	kset_set_kset_s(obj,subsys) - set kset for embedded kset.
 *	@obj:		ptr to some object type.
 *	@subsys:	a subsystem object (not a ptr).
 *
 *	Can be used for any object type with an embedded ->kset.
 *	Sets the kset of @obj's  embedded kobject (via its embedded
 *	kset) to @subsys.kset. This makes @obj a member of that 
 *	kset.
 */

#define kset_set_kset_s(obj,subsys) \
	(obj)->kset.kobj.kset = &(subsys).kset

/**
 *	subsys_set_kset(obj,subsys) - set kset for subsystem
 *	@obj:		ptr to some object type.
 *	@subsys:	a subsystem object (not a ptr).
 *
 *	Can be used for any object type with an embedded ->subsys.
 *	Sets the kset of @obj's kobject to @subsys.kset. This makes
 *	the object a member of that kset.
 */

#define subsys_set_kset(obj,_subsys) \
	(obj)->subsys.kset.kobj.kset = &(_subsys).kset

extern void subsystem_init(struct subsystem *);
extern int subsystem_register(struct subsystem *);
extern void subsystem_unregister(struct subsystem *);

static inline struct subsystem * subsys_get(struct subsystem * s)
{
	return s ? container_of(kset_get(&s->kset),struct subsystem,kset) : NULL;
}

static inline void subsys_put(struct subsystem * s)
{
	kset_put(&s->kset);
}

struct subsys_attribute {
	struct attribute attr;
	ssize_t (*show)(struct subsystem *, char *);
	ssize_t (*store)(struct subsystem *, const char *, size_t); 
};

extern int subsys_create_file(struct subsystem * , struct subsys_attribute *);
extern void subsys_remove_file(struct subsystem * , struct subsys_attribute *);

#ifdef CONFIG_HOTPLUG
void kobject_hotplug(struct kobject *kobj, enum kobject_action action);
int add_hotplug_env_var(char **envp, int num_envp, int *cur_index,
			char *buffer, int buffer_size, int *cur_len,
			const char *format, ...)
	__attribute__((format (printf, 7, 8)));
#else
static inline void kobject_hotplug(struct kobject *kobj, enum kobject_action action) { }
static inline int add_hotplug_env_var(char **envp, int num_envp, int *cur_index, 
				      char *buffer, int buffer_size, int *cur_len, 
				      const char *format, ...)
{ return 0; }
#endif

#endif /* __KERNEL__ */
#endif /* _KOBJECT_H_ */
