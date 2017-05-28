#ifndef _RAID0_H
#define _RAID0_H

#include <linux/raid/md.h>

/* RAID0�е��������������� */
struct strip_zone
{
	/* ��ǰ��������ʼ��ţ�������Ϊ��λ */
	sector_t zone_offset;	/* Zone offset in md_dev */
	/* ����������ʵ�����ϵ���ʼλ�� */
	sector_t dev_offset;	/* Zone offset in real dev */
	/* �������� */
	sector_t size;		/* Zone size */
	/* �����������Ĵ��̸��� */
	int nb_dev;		/* # of devices attached to the zone */
	/* �����������������豸 */
	mdk_rdev_t **dev;	/* Devices attached to the zone */
};

/* RAID0˽�����ݽṹ������ */
struct raid0_private_data
{
	struct strip_zone **hash_table; /* Table of indexes into strip_zone */
	/* ������������ */
	struct strip_zone *strip_zone;
	/* ��Ա�������� */
	mdk_rdev_t **devlist; /* lists of rdevs, pointed to by strip_zone->dev */
	/* ����������Ŀ */
	int nr_strip_zones;

	sector_t hash_spacing;
	int preshift;			/* shift this before divide by hash_spacing */
};

typedef struct raid0_private_data raid0_conf_t;

#define mddev_to_conf(mddev) ((raid0_conf_t *) mddev->private)

#endif
