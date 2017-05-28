#ifndef _LINUX_CDEV_H
#define _LINUX_CDEV_H
#ifdef __KERNEL__

/**
 * �ַ��豸��������������
 */
struct cdev {
	/**
	 * ��Ƕ��kobject
	 */
	struct kobject kobj;
	/**
	 * ָ��ʵ����������ģ���ָ��(����еĻ�)
	 */
	struct module *owner;
	/**
	 * ָ���豸���������ļ��������ָ��
	 */
	struct file_operations *ops;
	/**
	 * ���ַ��豸�ļ���Ӧ��������������ͷ
	 */
	struct list_head list;
	/**
	 * ���豸��������������ĳ�ʼ���豸�ʺʹ��豸��
	 */
	dev_t dev;
	/**
	 * ���豸����������������豸�ŷ�Χ�Ĵ�С
	 */
	unsigned int count;
};

void cdev_init(struct cdev *, struct file_operations *);

struct cdev *cdev_alloc(void);

void cdev_put(struct cdev *p);

int cdev_add(struct cdev *, dev_t, unsigned);

void cdev_del(struct cdev *);

void cd_forget(struct inode *);

#endif
#endif
