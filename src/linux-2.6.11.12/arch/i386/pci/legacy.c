/*
 * legacy.c - traditional, old school PCI bus probing
 */
#include <linux/init.h>
#include <linux/pci.h>
#include "pci.h"

/*
 * Discover remaining PCI buses in case there are peer host bridges.
 * We use the number of last PCI bus provided by the PCI BIOS.
 */
static void __devinit pcibios_fixup_peer_bridges(void)
{
	int n, devfn;

	if (pcibios_last_bus <= 0 || pcibios_last_bus >= 0xff)
		return;
	DBG("PCI: Peer bridge fixup\n");

	for (n=0; n <= pcibios_last_bus; n++) {
		u32 l;
		if (pci_find_bus(0, n))
			continue;
		for (devfn = 0; devfn < 256; devfn += 8) {
			if (!raw_pci_ops->read(0, n, devfn, PCI_VENDOR_ID, 2, &l) &&
			    l != 0x0000 && l != 0xffff) {
				DBG("Found device at %02x:%02x [%04x]\n", n, devfn, l);
				printk(KERN_INFO "PCI: Discovered peer bus %02x\n", n);
				pci_scan_bus(n, &pci_root_ops, NULL);
				break;
			}
		}
	}
}

/**
 * ��ɶ�PCI���ߵ�ö�٣�����proc�ļ�ϵͳ��sysfs�ļ�ϵͳ�н�����Ӧ�Ľṹ��
 * ���û��ʹ��ACPI���ƣ���˺����Ƕ�PCI���߽��г�ʼ������Ҫ������
 */
static int __init pci_legacy_init(void)
{
	if (!raw_pci_ops) {
		printk("PCI: System does not support PCI\n");
		return 0;
	}

	/**
	 * ������ACPI��pcibios_scannedĬ�Ͼ���1����������ֱ�ӷ��ء�
	 */
	if (pcibios_scanned++)
		return 0;

	printk("PCI: Probing PCI hardware\n");
	/**
	 * ��ɶ�PCI��������ö�١����Ϊ0��ʾ�����ߺ�0��ʼ����ö�١�
	 * pcibios_scan_root�������pci_bus_add_devices��PCI�����ϵ��豸���뵽sysfs�ļ�ϵͳ�С�
	 */
	pci_root_bus = pcibios_scan_root(0);

	pcibios_fixup_peer_bridges();

	return 0;
}

subsys_initcall(pci_legacy_init);
