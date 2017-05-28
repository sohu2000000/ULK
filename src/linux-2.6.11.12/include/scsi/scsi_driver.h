#ifndef _SCSI_SCSI_DRIVER_H
#define _SCSI_SCSI_DRIVER_H

#include <linux/device.h>

struct module;
struct scsi_cmnd;


/* SCSI��������������SCSI��������������������SCSI�������� */
struct scsi_driver {
	/* ����ģ�� */
	struct module		*owner;
	/* ��Ƕ�豸���� */
	struct device_driver	gendrv;

	int (*init_command)(struct scsi_cmnd *);
	/* ��������ɨ��Ļص����� */
	void (*rescan)(struct device *);
	int (*issue_flush)(struct device *, sector_t *);
};
#define to_scsi_driver(drv) \
	container_of((drv), struct scsi_driver, gendrv)

extern int scsi_register_driver(struct device_driver *);
#define scsi_unregister_driver(drv) \
	driver_unregister(drv);

extern int scsi_register_interface(struct class_interface *);
#define scsi_unregister_interface(intf) \
	class_interface_unregister(intf)

#endif /* _SCSI_SCSI_DRIVER_H */
