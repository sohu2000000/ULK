#ifndef _LINEAR_H
#define _LINEAR_H

#include <linux/raid/md.h>

/* ����RAID��ÿ�����̵������� */
struct dev_info {
	/* �ó�Ա���̵�ͨ�������� */
	mdk_rdev_t	*rdev;
	/* ���� */
	sector_t	size;
	/* ��ʼ������ */
	sector_t	offset;
};

typedef struct dev_info dev_info_t;

/* ����RAID��˽�����ݽṹ */
struct linear_private_data
{
	dev_info_t		**hash_table;
	dev_info_t		*smallest;
	int			nr_zones;
	/* ��Ա�������� */
	dev_info_t		disks[0];
};


typedef struct linear_private_data linear_conf_t;

#define mddev_to_conf(mddev) ((linear_conf_t *) mddev->private)

#endif
