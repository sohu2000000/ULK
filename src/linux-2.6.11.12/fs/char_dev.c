/*
 *  linux/fs/char_dev.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/config.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/devfs_fs_kernel.h>

#include <linux/kobject.h>
#include <linux/kobj_map.h>
#include <linux/cdev.h>

#ifdef CONFIG_KMOD
#include <linux/kmod.h>
#endif

/**
 * kobj_map����һ��ɢ�б�����255���������0-255��Χ�����豸�Ž���������
 * ɢ�б���probe���͵Ķ���ÿ������ӵ��һ���Ѿ�ע������豸�źʹ��豸�š�
 * cdev_map���ַ��豸��kobjectӳ����
 */
static struct kobj_map *cdev_map;

#define MAX_PROBE_HASH 255	/* random */

static DEFINE_RWLOCK(chrdevs_lock);

/**
 * Ϊ�˼�¼�Ѿ�������Щ�ַ��豸�ţ��ں�ʹ��ɢ�б�chrdevs����Ĵ�С�������豸�ŷ�Χ��
 * ������ͬ���豸�ŷ�Χ���ܹ���ͬһ�����豸�ţ����Ƿ�Χ�����ص���
 * chrdevs����255���������ɢ�к������������豸�ŵĸ���λ�������Ҫ���豸����ɢ�С�
 * ��ͻ�����ÿһ����һ��char_device_struct
 */
static struct char_device_struct {
	/**
	 * ��ͻ��������һ��Ԫ�ص�ָ��
	 */
	struct char_device_struct *next;
	/**
	 * �豸�ŷ�Χ�ڵ����豸��
	 */
	unsigned int major;
	/**
	 * �豸�ŷ�Χ�ڵĳ�ʼ���豸��
	 */
	unsigned int baseminor;
	/**
	 * �豸�ŷ�Χ�Ĵ�С
	 */
	int minorct;
	/**
	 * �����豸�ŷ�Χ�ڵ��豸�������������
	 */
	const char *name;
	/**
	 * û��ʹ��
	 */
	struct file_operations *fops;
	/**
	 * ָ���ַ��豸����������������ָ��
	 */
	struct cdev *cdev;		/* will die */
} *chrdevs[MAX_PROBE_HASH];

/* index in the above */
static inline int major_to_index(int major)
{
	return major % MAX_PROBE_HASH;
}

/* get char device names in somewhat random order */
int get_chrdev_list(char *page)
{
	struct char_device_struct *cd;
	int i, len;

	len = sprintf(page, "Character devices:\n");

	read_lock(&chrdevs_lock);
	for (i = 0; i < ARRAY_SIZE(chrdevs) ; i++) {
		for (cd = chrdevs[i]; cd; cd = cd->next)
			len += sprintf(page+len, "%3d %s\n",
				       cd->major, cd->name);
	}
	read_unlock(&chrdevs_lock);

	return len;
}

/*
 * Register a single major with a specified minor range.
 *
 * If major == 0 this functions will dynamically allocate a major and return
 * its number.
 *
 * If major > 0 this function will attempt to reserve the passed range of
 * minors and will return zero on success.
 *
 * Returns a -ve errno on failure.
 */
/**
 * Ϊ�ַ��豸�����������һ����Χ�ڵ��豸�š������µ���������ʹ�ö���Ӧ��ʹ�����ַ���������register_chrdev
 */
static struct char_device_struct *
__register_chrdev_region(unsigned int major, unsigned int baseminor,
			   int minorct, const char *name)
{
	struct char_device_struct *cd, **cp;
	int ret = 0;
	int i;

	/**
	 * ����һ���µ�char_device_struct�ṹ����0���
	 */
	cd = kmalloc(sizeof(struct char_device_struct), GFP_KERNEL);
	if (cd == NULL)
		return ERR_PTR(-ENOMEM);

	memset(cd, 0, sizeof(struct char_device_struct));

	write_lock_irq(&chrdevs_lock);

	/* temporary */
	/**
	 * ���豸��Ϊ0����ô����̬����һ���豸��
	 * ������ĩβ�ʼ������ǰѰ��һ����δʹ�õ����豸�Ŷ�Ӧ�Ŀճ�ͻ����û���ҵ��ͷ��ش���
	 */
	if (major == 0) {
		for (i = ARRAY_SIZE(chrdevs)-1; i > 0; i--) {
			if (chrdevs[i] == NULL)
				break;
		}

		if (i == 0) {
			ret = -EBUSY;
			goto out;
		}
		major = i;
		ret = major;
	}

	/**
	 * ��ʼ��char_device_struct�ṹ�еĳ�ʼ�豸�š���Χ��С��������������
	 */
	cd->major = major;
	cd->baseminor = baseminor;
	cd->minorct = minorct;
	cd->name = name;

	/**
	 * ִ��ɢ�к������������豸�Ŷ�Ӧ��ɢ�б�����
	 */
	i = major_to_index(major);

	/**
	 * ������ͻ����Ϊ�µĽṹѰ����ȷ��λ��
	 */
	for (cp = &chrdevs[i]; *cp; cp = &(*cp)->next)
		if ((*cp)->major > major ||
		    ((*cp)->major == major && (*cp)->baseminor >= baseminor))
			break;
	/**
	 * ����ҵ���������豸�ŷ�Χ�ص��ķ�Χ���򷵻ش���
	 */
	if (*cp && (*cp)->major == major &&
	    (*cp)->baseminor < baseminor + minorct) {
		ret = -EBUSY;
		goto out;
	}
	/*
	 * ���µ�char_device_struct�����������ͻ��
	 */
	cd->next = *cp;
	*cp = cd;
	write_unlock_irq(&chrdevs_lock);
	/*
	 * �����µ�char_device_struct��ַ
	 */
	return cd;
out:
	write_unlock_irq(&chrdevs_lock);
	kfree(cd);
	return ERR_PTR(ret);
}

static struct char_device_struct *
__unregister_chrdev_region(unsigned major, unsigned baseminor, int minorct)
{
	struct char_device_struct *cd = NULL, **cp;
	int i = major_to_index(major);

	write_lock_irq(&chrdevs_lock);
	for (cp = &chrdevs[i]; *cp; cp = &(*cp)->next)
		if ((*cp)->major == major &&
		    (*cp)->baseminor == baseminor &&
		    (*cp)->minorct == minorct)
			break;
	if (*cp) {
		cd = *cp;
		*cp = cd->next;
	}
	write_unlock_irq(&chrdevs_lock);
	return cd;
}

/**
 * register_chrdev_region����������������ʼ�豸�ţ��豸�ŷ�Χ��С����������
 * Ϊ�ַ��豸�����豸�š���������Ӧ��ʹ�����������
 */
int register_chrdev_region(dev_t from, unsigned count, const char *name)
{
	struct char_device_struct *cd;
	dev_t to = from + count;
	dev_t n, next;

	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		if (next > to)
			next = to;
		cd = __register_chrdev_region(MAJOR(n), MINOR(n),
			       next - n, name);
		if (IS_ERR(cd))
			goto fail;
	}
	return 0;
fail:
	to = n;
	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		kfree(__unregister_chrdev_region(MAJOR(n), MINOR(n), next - n));
	}
	return PTR_ERR(cd);
}

/**
 * alloc_chrdev_region��register_chrdev_region���ƣ����������Զ�̬�ķ���һ�����豸�š�
 * �����յĲ���Ϊ�豸�ŷ�Χ�ڵĳ�ʼ���豸�ţ���Χ�Ĵ�С��������������ơ�
 */
int alloc_chrdev_region(dev_t *dev, unsigned baseminor, unsigned count,
			const char *name)
{
	struct char_device_struct *cd;
	cd = __register_chrdev_region(0, baseminor, count, name);
	if (IS_ERR(cd))
		return PTR_ERR(cd);
	*dev = MKDEV(cd->major, cd->baseminor);
	return 0;
}

/**
 * ע��һ���ַ��豸����������Ϸ�����
 * Ϊ���������豸��ע��0��255Ϊ���豸�š���Ϊÿ���豸����һ����Ӧ��Ĭ��cdev�ṹ��
 * ʹ����һ�ӿڵ����������ܹ���������256�����豸���ϵ�open����(��ʹû�ж�Ӧ��ʵ���豸)��Ҳ����ʹ�ô���255�����豸�źʹ��豸�š�
 *		major:		�豸�����豸�š�
 *		name:		������������ơ�
 *		fops:		Ĭ�ϵ�file_operations�ṹ��
 */
int register_chrdev(unsigned int major, const char *name,
		    struct file_operations *fops)
{
	struct char_device_struct *cd;
	struct cdev *cdev;
	char *s;
	int err = -ENOMEM;

	/**
	 * ����__register_chrdev_region����������豸�ŷ�Χ��
	 */
	cd = __register_chrdev_region(major, 0, 256, name);
	if (IS_ERR(cd))/* �豸�ų�ͻ�����ء� */
		return PTR_ERR(cd);

	/* Ϊ�豸�����������һ���µ�cdev�ṹ����kobject��������Ϊktype_cdev_dynamic*/
	cdev = cdev_alloc();
	if (!cdev)
		goto out2;

	/* ��ʼ��cdev�ṹ */
	cdev->owner = fops->owner;
	cdev->ops = fops;
	kobject_set_name(&cdev->kobj, "%s", name);
	for (s = strchr(kobject_name(&cdev->kobj),'/'); s; s = strchr(s, '/'))
		*s = '!';

	/* ���豸��ӵ��豸����ģ���� */
	err = cdev_add(cdev, MKDEV(cd->major, 0), 256);
	if (err)
		goto out;

    /*
     * �����豸�ŷ�Χ������char_device_struct���ַ��豸����������cdev
	 */
	cd->cdev = cdev;

    /*���ط�����豸�ŷ�Χ�����豸��*/
	return major ? 0 : cd->major;
out:
	kobject_put(&cdev->kobj);
out2:
	kfree(__unregister_chrdev_region(cd->major, 0, 256));
	return err;
}

/**
 * ��register_chrdev�豸��Ӧ���Ƴ�������
 */
void unregister_chrdev_region(dev_t from, unsigned count)
{
	dev_t to = from + count;
	dev_t n, next;

	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		if (next > to)
			next = to;
		kfree(__unregister_chrdev_region(MAJOR(n), MINOR(n), next - n));
	}
}

int unregister_chrdev(unsigned int major, const char *name)
{
	struct char_device_struct *cd;
	cd = __unregister_chrdev_region(major, 0, 256);
	if (cd && cd->cdev)
		cdev_del(cd->cdev);
	kfree(cd);
	return 0;
}

static DEFINE_SPINLOCK(cdev_lock);

static struct kobject *cdev_get(struct cdev *p)
{
	struct module *owner = p->owner;
	struct kobject *kobj;

	if (owner && !try_module_get(owner))
		return NULL;
	kobj = kobject_get(&p->kobj);
	if (!kobj)
		module_put(owner);
	return kobj;
}

void cdev_put(struct cdev *p)
{
	if (p) {
		kobject_put(&p->kobj);
		module_put(p->owner);
	}
}

/*
 * Called every time a character special file is opened
 */
/**
 * �ַ��豸�Ĵ򿪷�����open���ô���dentry_open��dentry_open����def_chr_fops���е�open�ֶμ���������
 * inode-�������ĵ�ַ
 * filp-�򿪵��ļ�ָ��
 */
int chrdev_open(struct inode * inode, struct file * filp)
{
	struct cdev *p;
	struct cdev *new = NULL;
	int ret = 0;

	spin_lock(&cdev_lock);
	/**
	 * ���inode->i_cdev,�����Ϊ�գ���ʾinode�ṹ�Ѿ������ʣ�������cdev�����ü���
	 */
	p = inode->i_cdev;
	if (!p) {
		struct kobject *kobj;
		int idx;
		spin_unlock(&cdev_lock);
		/**
		 * ����kobj_lookup�����������豸�����ڵķ�Χ��
		 */
		kobj = kobj_lookup(cdev_map, inode->i_rdev, &idx);
		/**
		 * �÷�Χ�����ڣ�ֱ�ӷ��ش���
		 */
		if (!kobj)
			return -ENXIO;
		/**
		 * ��Χ���ڣ�������÷�Χ���Ӧ��cdev�������ĵ�ַ��
		 */
		new = container_of(kobj, struct cdev, kobj);
		spin_lock(&cdev_lock);
		p = inode->i_cdev;
		if (!p) {
			/**
			 * inodeû�б����ʹ������ҵ���cdev��������ַ��Ϊinode->i_cdev
			 */
			inode->i_cdev = p = new;
			/**
			 * ������i_cindex
			 */
			inode->i_cindex = idx;
			/**
			 * ��inode������뵽cdev��������list������
			 */
			list_add(&inode->i_devices, &p->list);
			new = NULL;
		} else if (!cdev_get(p))
			ret = -ENXIO;
	} else if (!cdev_get(p))
		ret = -ENXIO;
	spin_unlock(&cdev_lock);
	cdev_put(new);
	if (ret)
		return ret;
	/**
	 * ��ʼ���ļ�����ָ��
	 */
	filp->f_op = fops_get(p->ops);
	if (!filp->f_op) {
		cdev_put(p);
		return -ENXIO;
	}
	/**
	 * ������open��������ִ������
	 */
	if (filp->f_op->open) {
		lock_kernel();
		/**
		 * ����豸����������һ�����ϵ��豸�ţ��򱾺���һ����ٴ�����file��f_op
		 */
		ret = filp->f_op->open(inode,filp);
		unlock_kernel();
	}
	if (ret)
		cdev_put(p);
	/**
	 * �ɹ�������������񣬷���0����filp->f_op->open�Ľ��
	 */
	return ret;
}

void cd_forget(struct inode *inode)
{
	spin_lock(&cdev_lock);
	list_del_init(&inode->i_devices);
	inode->i_cdev = NULL;
	spin_unlock(&cdev_lock);
}

void cdev_purge(struct cdev *cdev)
{
	spin_lock(&cdev_lock);
	while (!list_empty(&cdev->list)) {
		struct inode *inode;
		inode = container_of(cdev->list.next, struct inode, i_devices);
		list_del_init(&inode->i_devices);
		inode->i_cdev = NULL;
	}
	spin_unlock(&cdev_lock);
}

/*
 * Dummy default file-operations: the only thing this does
 * is contain the open that then fills in the correct operations
 * depending on the special file...
 */
struct file_operations def_chr_fops = {
	.open = chrdev_open,
};

static struct kobject *exact_match(dev_t dev, int *part, void *data)
{
	struct cdev *p = data;
	return &p->kobj;
}

static int exact_lock(dev_t dev, void *data)
{
	struct cdev *p = data;
	return cdev_get(p) ? 0 : -1;
}

/**
 * ���豸��������ģ����ע��һ��cdev��������
 * ����ʼ��cdev�������е�dev��count�ֶΣ�Ȼ�����kobj_map������
 * kobj_map���ν����豸��������ģ�͵����ݽṹ�����豸�ŷ�Χ���Ƶ��豸����������������С�
 * �豸��������ģ��Ϊ�ַ��豸������һ��kobjectӳ���򣬸�ӳ������һ��kobj_map���͵�����������������ȫ������cdev_map����
 * count����Ϊ1������Ҳ�������������SCSI�Ŵ�����������ͨ��ÿ�������豸�Ķ�����豸�������û��ռ�ѡ��ͬ�Ĳ���ģʽ(���ܶ�)
 */
int cdev_add(struct cdev *p, dev_t dev, unsigned count)
{
	p->dev = dev;
	p->count = count;
	return kobj_map(cdev_map, dev, count, NULL, exact_match, exact_lock, p);
}

static void cdev_unmap(dev_t dev, unsigned count)
{
	kobj_unmap(cdev_map, dev, count);
}

/**
 * ��ϵͳ���Ƴ�һ���ַ��豸��
 */
void cdev_del(struct cdev *p)
{
	cdev_unmap(p->dev, p->count);
	kobject_put(&p->kobj);
}


static decl_subsys(cdev, NULL, NULL);

static void cdev_default_release(struct kobject *kobj)
{
	struct cdev *p = container_of(kobj, struct cdev, kobj);
	cdev_purge(p);
}

static void cdev_dynamic_release(struct kobject *kobj)
{
	struct cdev *p = container_of(kobj, struct cdev, kobj);
	cdev_purge(p);
	kfree(p);
}

static struct kobj_type ktype_cdev_default = {
	.release	= cdev_default_release,
};

static struct kobj_type ktype_cdev_dynamic = {
	.release	= cdev_dynamic_release,
};

/**
 * ��̬����cdev������������ʼ����Ƕ��kobject���ݽṹ�������ü���Ϊ0ʱ����Զ��ͷŸ�������
 */
struct cdev *cdev_alloc(void)
{
	struct cdev *p = kmalloc(sizeof(struct cdev), GFP_KERNEL);
	if (p) {
		memset(p, 0, sizeof(struct cdev));
		p->kobj.ktype = &ktype_cdev_dynamic;
		INIT_LIST_HEAD(&p->list);
		kobject_init(&p->kobj);
	}
	return p;
}

/**
 * ��ʼ��cdev����������cdev��������Ƕ���������ṹ��ʱ���������õķ�����
 */
void cdev_init(struct cdev *cdev, struct file_operations *fops)
{
	memset(cdev, 0, sizeof *cdev);
	INIT_LIST_HEAD(&cdev->list);
	cdev->kobj.ktype = &ktype_cdev_default;
	kobject_init(&cdev->kobj);
	cdev->ops = fops;
}

static struct kobject *base_probe(dev_t dev, int *part, void *data)
{
	if (request_module("char-major-%d-%d", MAJOR(dev), MINOR(dev)) > 0)
		/* Make old-style 2.4 aliases work */
		request_module("char-major-%d", MAJOR(dev));
	return NULL;
}

void __init chrdev_init(void)
{
/*
 * Keep cdev_subsys around because (and only because) the kobj_map code
 * depends on the rwsem it contains.  We don't make it public in sysfs,
 * however.
 */
	subsystem_init(&cdev_subsys);
	cdev_map = kobj_map_init(base_probe, &cdev_subsys);
}


/* Let modules do char dev stuff */
EXPORT_SYMBOL(register_chrdev_region);
EXPORT_SYMBOL(unregister_chrdev_region);
EXPORT_SYMBOL(alloc_chrdev_region);
EXPORT_SYMBOL(cdev_init);
EXPORT_SYMBOL(cdev_alloc);
EXPORT_SYMBOL(cdev_del);
EXPORT_SYMBOL(cdev_add);
EXPORT_SYMBOL(register_chrdev);
EXPORT_SYMBOL(unregister_chrdev);
