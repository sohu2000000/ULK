/*
 * Device tables which are exported to userspace via
 * scripts/table2alias.c.  You must keep that file in sync with this
 * header.
 */

#ifndef LINUX_MOD_DEVICETABLE_H
#define LINUX_MOD_DEVICETABLE_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef unsigned long kernel_ulong_t;
#endif

#define PCI_ANY_ID (~0)

/**
 * �豸��ʶ�š��ⲻ��Linux�ж����ID,������PCI��׼�ж����ID��
 */
struct pci_device_id {
	/**
	 * vendor��device�Ѿ��㹻Ψһ��ʶһ���豸
	 */
	__u32 vendor, device;		/* Vendor and device ID or PCI_ANY_ID*/
	/**
	 * subvendor��subdevice���ٻ�ʹ�õ�������ͨ���ᱻ�ó�ƥ�������豸(PCI_ANY_ID)
	 */
	__u32 subvendor, subdevice;	/* Subsystem ID's or PCI_ANY_ID */
	/**
	 * class��class_mark��ʾ����豸�����ĸ����,��NETWORK.
	 */
	__u32 class, class_mask;	/* (class,subclass,prog-if) triplet */
	/**
	 * driver_data����PCIID��һ���֣������豸ʹ�õ�˽�в�����
	 */
	kernel_ulong_t driver_data;	/* Data private to the driver */
};


#define IEEE1394_MATCH_VENDOR_ID	0x0001
#define IEEE1394_MATCH_MODEL_ID		0x0002
#define IEEE1394_MATCH_SPECIFIER_ID	0x0004
#define IEEE1394_MATCH_VERSION		0x0008

struct ieee1394_device_id {
	__u32 match_flags;
	__u32 vendor_id;
	__u32 model_id;
	__u32 specifier_id;
	__u32 version;
	kernel_ulong_t driver_data;
};


/*
 * Device table entry for "new style" table-driven USB drivers.
 * User mode code can read these tables to choose which modules to load.
 * Declare the table as a MODULE_DEVICE_TABLE.
 *
 * A probe() parameter will point to a matching entry from this table.
 * Use the driver_info field for each match to hold information tied
 * to that match:  device quirks, etc.
 *
 * Terminate the driver's table with an all-zeroes entry.
 * Use the flag values to control which fields are compared.
 */

/**
 * struct usb_device_id - identifies USB devices for probing and hotplugging
 * @match_flags: Bit mask controlling of the other fields are used to match
 *	against new devices.  Any field except for driver_info may be used,
 *	although some only make sense in conjunction with other fields.
 *	This is usually set by a USB_DEVICE_*() macro, which sets all
 *	other fields in this structure except for driver_info.
 * @idVendor: USB vendor ID for a device; numbers are assigned
 *	by the USB forum to its members.
 * @idProduct: Vendor-assigned product ID.
 * @bcdDevice_lo: Low end of range of vendor-assigned product version numbers.
 *	This is also used to identify individual product versions, for
 *	a range consisting of a single device.
 * @bcdDevice_hi: High end of version number range.  The range of product
 *	versions is inclusive.
 * @bDeviceClass: Class of device; numbers are assigned
 *	by the USB forum.  Products may choose to implement classes,
 *	or be vendor-specific.  Device classes specify behavior of all
 *	the interfaces on a devices.
 * @bDeviceSubClass: Subclass of device; associated with bDeviceClass.
 * @bDeviceProtocol: Protocol of device; associated with bDeviceClass.
 * @bInterfaceClass: Class of interface; numbers are assigned
 *	by the USB forum.  Products may choose to implement classes,
 *	or be vendor-specific.  Interface classes specify behavior only
 *	of a given interface; other interfaces may support other classes.
 * @bInterfaceSubClass: Subclass of interface; associated with bInterfaceClass.
 * @bInterfaceProtocol: Protocol of interface; associated with bInterfaceClass.
 * @driver_info: Holds information used by the driver.  Usually it holds
 *	a pointer to a descriptor understood by the driver, or perhaps
 *	device flags.
 *
 * In most cases, drivers will create a table of device IDs by using
 * USB_DEVICE(), or similar macros designed for that purpose.
 * They will then export it to userspace using MODULE_DEVICE_TABLE(),
 * and provide it to the USB core through their usb_driver structure.
 *
 * See the usb_match_id() function for information about how matches are
 * performed.  Briefly, you will normally use one of several macros to help
 * construct these entries.  Each entry you provide will either identify
 * one or more specific products, or will identify a class of products
 * which have agreed to behave the same.  You should put the more specific
 * matches towards the beginning of your table, so that driver_info can
 * record quirks of specific products.
 */
/**
 * �ṩ��һ�в�ͬ���͵���������֧�ֵ�USB�豸��USB����ʹ�ø��б����ж϶���һ���豸����ʹ����һ����������
 * �Ȳ���ű�ʹ������ȷ����һ���ض����豸���뵽ϵͳʱ���Զ�װ����һ����������
 */
struct usb_device_id {
	/* which fields to match against? */
	/**
	 * ȷ���豸�ͽṹ���������ֶ��е���һ����ƥ�䡣��Щ�ֶ���USB_DEVICE_ID_MATCH_*�����λ�ֶΡ�
	 * ͨ����ֱ�����ø��ֶΣ�����ʹ��USB_DEVICE������ʼ����
	 */
	__u16		match_flags;

	/* Used for product specific matches; range is inclusive */
	/**
	 * �豸��USB������ID���ñ������USB��ָ̳�ɸ����Ա�ġ�
	 */
	__u16		idVendor;
	/**
	 * �豸��USB��ƷID������ָ����������ID�������̶���������ĸ������ƷID��
	 */
	__u16		idProduct;
	/**
	 * ������������ָ�ɵĲ�Ʒ�İ汾�з�Χ�����ֵ�����ֵ����ʽΪBCD��
	 */
	__u16		bcdDevice_lo;
	__u16		bcdDevice_hi;

	/* Used for device class matches */
	/**
	 * �ֱ����豸�����͡������ͺ�Э�顣��Щ�����USB��ָ̳�ɣ�������USB�淶�С���ϸ˵���������豸����Ϊ���������豸�ϵ����нӿڡ�
	 */
	__u8		bDeviceClass;
	__u8		bDeviceSubClass;
	__u8		bDeviceProtocol;

	/* Used for interface class matches */
	/**
	 * �ֱ������͡������ͺ͵����ӿڵ�Э�顣��Щ�����USB��ָ̳�ɣ�������USB�淶�С�
	 */
	__u8		bInterfaceClass;
	__u8		bInterfaceSubClass;
	__u8		bInterfaceProtocol;

	/* not matched against */
	/** 
	 * ��ֵ���������Ƚ��Ƿ�ƥ��ģ�����������������������USB���������̽��ص������п����������ֲ�ͬ�豸����Ϣ��
	 */
	kernel_ulong_t	driver_info;
};

/* Some useful macros to use to create struct usb_device_id */
#define USB_DEVICE_ID_MATCH_VENDOR		0x0001
#define USB_DEVICE_ID_MATCH_PRODUCT		0x0002
#define USB_DEVICE_ID_MATCH_DEV_LO		0x0004
#define USB_DEVICE_ID_MATCH_DEV_HI		0x0008
#define USB_DEVICE_ID_MATCH_DEV_CLASS		0x0010
#define USB_DEVICE_ID_MATCH_DEV_SUBCLASS	0x0020
#define USB_DEVICE_ID_MATCH_DEV_PROTOCOL	0x0040
#define USB_DEVICE_ID_MATCH_INT_CLASS		0x0080
#define USB_DEVICE_ID_MATCH_INT_SUBCLASS	0x0100
#define USB_DEVICE_ID_MATCH_INT_PROTOCOL	0x0200

/* s390 CCW devices */
struct ccw_device_id {
	__u16	match_flags;	/* which fields to match against */

	__u16	cu_type;	/* control unit type     */
	__u16	dev_type;	/* device type           */
	__u8	cu_model;	/* control unit model    */
	__u8	dev_model;	/* device model          */

	kernel_ulong_t driver_info;
};

#define CCW_DEVICE_ID_MATCH_CU_TYPE		0x01
#define CCW_DEVICE_ID_MATCH_CU_MODEL		0x02
#define CCW_DEVICE_ID_MATCH_DEVICE_TYPE		0x04
#define CCW_DEVICE_ID_MATCH_DEVICE_MODEL	0x08


#define PNP_ID_LEN	8
#define PNP_MAX_DEVICES	8

struct pnp_device_id {
	__u8 id[PNP_ID_LEN];
	kernel_ulong_t driver_data;
};

struct pnp_card_device_id {
	__u8 id[PNP_ID_LEN];
	kernel_ulong_t driver_data;
	struct {
		__u8 id[PNP_ID_LEN];
	} devs[PNP_MAX_DEVICES];
};


#endif /* LINUX_MOD_DEVICETABLE_H */
