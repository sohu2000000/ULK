/*
 *	Low-Level PCI Access for i386 machines.
 *
 *	(c) 1999 Martin Mares <mj@ucw.cz>
 */

#undef DEBUG

#ifdef DEBUG
#define DBG(x...) printk(x)
#else
#define DBG(x...)
#endif

#define PCI_PROBE_BIOS		0x0001
#define PCI_PROBE_CONF1		0x0002
#define PCI_PROBE_CONF2		0x0004
#define PCI_PROBE_MMCONF	0x0008
#define PCI_PROBE_MASK		0x000f

#define PCI_NO_SORT		0x0100
#define PCI_BIOS_SORT		0x0200
#define PCI_NO_CHECKS		0x0400
#define PCI_USE_PIRQ_MASK	0x0800
#define PCI_ASSIGN_ROMS		0x1000
#define PCI_BIOS_IRQ_SCAN	0x2000
#define PCI_ASSIGN_ALL_BUSSES	0x4000

extern unsigned int pci_probe;

/* pci-i386.c */

extern unsigned int pcibios_max_latency;

void pcibios_resource_survey(void);
int pcibios_enable_resources(struct pci_dev *, int);

/* pci-pc.c */

extern int pcibios_last_bus;
extern struct pci_bus *pci_root_bus;
extern struct pci_ops pci_root_ops;

/* pci-irq.c */

/* PCI��۵�IRQ������ */
struct irq_info {
	/* ���ߣ����/���ܱ�� */
	u8 bus, devfn;			/* Bus, device and function */
	struct {
		/* ��·ֵ��������оƬ�飬0��ʾδ·�� */
		u8 link;		/* IRQ line ID, chipset dependent, 0=not routed */
		/* ����ʹ�õ�IRQ���λͼ */
		u16 bitmap;		/* Available IRQs */
	} __attribute__((packed)) irq[4];
	/* ��۱�ţ�0��ʾ�����豸 */
	u8 slot;			/* Slot number, 0=onboard */
	/* ����δ�� */
	u8 rfu;
} __attribute__((packed));

/* �ж�·�ɱ���Ҫ��BIOS ROM�в��Ҹñ� */
struct irq_routing_table {
	/* ǩ����������"$PIR" */
	u32 signature;			/* PIRQ_SIGNATURE should be here */
	/* �汾�� */
	u16 version;			/* PIRQ_VERSION */
	/* ���ֽ�Ϊ��λ�ı��� */
	u16 size;			/* Table size in bytes */
	/* �ж�·�����������߱�źͲ��/���ܱ�� */
	u8 rtr_bus, rtr_devfn;		/* Where the interrupt router lies */
	/* ������IRQλͼ��Ϊ1��ʾ��Ӧ����Ӧ��ר�� */
	u16 exclusive_irqs;		/* IRQs devoted exclusively to PCI usage */
	/* �ж�·�����ĳ���ID���豸ID */
	u16 rtr_vendor, rtr_device;	/* Vendor and device ID of interrupt router */
	/* δ�� */
	u32 miniport_data;		/* Crap */
	/* ����δ�� */
	u8 rfu[11];
	/* У��ͣ�����Ϊ0 */
	u8 checksum;			/* Modulo 256 checksum must give zero */
	/* �ж�·�ɱ��ÿ��PCI���ռ��һ�� */
	struct irq_info slots[0];
} __attribute__((packed));

extern unsigned int pcibios_irq_mask;

extern int pcibios_scanned;
extern spinlock_t pci_config_lock;

extern int (*pcibios_enable_irq)(struct pci_dev *dev);
