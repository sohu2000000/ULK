#ifndef _LINUX_IN_ROUTE_H
#define _LINUX_IN_ROUTE_H

/* IPv4 routing cache flags */

#define RTCF_DEAD	RTNH_F_DEAD
#define RTCF_ONLINK	RTNH_F_ONLINK

/* Obsolete flag. About to be deleted */
#define RTCF_NOPMTUDISC RTM_F_NOPMTUDISC

/**
 * ·�ɱ�������б仯ͨ��Netlink֪ͨ������Ȥ���û��ռ�Ӧ�ó���
 * ��ѡ�û����ȫʵ�֡���������ip route get 10.0.1.0/24 notify�����������øñ�־��
 */
#define RTCF_NOTIFY	0x00010000
/**
 * δʹ�á�
 */
#define RTCF_DIRECTDST	0x00020000
/**
 * �Խ��յ���ICMP_REDIRECT��Ϣ������Ӧ�����һ��·�ɱ���
 */
#define RTCF_REDIRECTED	0x00040000
/**
 * δʹ�á�
 */
#define RTCF_TPROXY	0x00080000

/**
 * δʹ�á��ñ�־�Ѿ������������øñ�־�����ڱ��һ��·�ɶԿ��ٽ�����Fast Switching���Ϸ���
 * ���ٽ��������Ѿ���2.6�ں��б�������
 */
#define RTCF_FAST	0x00200000
/**
 * ���ٱ�IPv4ʹ�á��ñ�־�����ڱ�Ǳ���������masqueradedԴ��ַ��
 */
#define RTCF_MASQ	0x00400000
/**
 * ��Щ��־���ٱ�IPv4ʹ�á�������ǰ��FastNAT����ʹ�ã���������2.6�ں����Ѿ���ɾ��
 */
#define RTCF_SNAT	0x00800000
/**
 * ��������Դվ�ͻ�ICMP_REDIRECT��Ϣʱ��ip_route_input_slow���øñ�־��
 * ip_forward���ݸñ�־��������Ϣ�������Ƿ���Ҫ����ICMP�ض�����Ϣ��
 */
#define RTCF_DOREDIRECT 0x01000000
/**
 * �ñ�־��Ҫ���ڸ���ICMP���룬��Ӧ���Ե�ַ����������Ϣ������Ӧ��
 * ÿ������fib_validate_source��鵽���ձ��ĵ�Դ��ַͨ��һ���������÷�Χ��RT_SCOPE_HOST������һ���ǿɴ�ʱ�������øñ�־��
 */
#define RTCF_DIRECTSRC	0x04000000
/**
 * ��Щ��־���ٱ�IPv4ʹ�á�������ǰ��FastNAT����ʹ�ã���������2.6�ں����Ѿ���ɾ��
 */
#define RTCF_DNAT	0x08000000
/**
 * ·�ɵ�Ŀ�ĵ�ַ��һ���㲥��ַ��
 */
#define RTCF_BROADCAST	0x10000000
/**
 * ·�ɵ�Ŀ�ĵ�ַ��һ���ಥ��ַ��
 */
#define RTCF_MULTICAST	0x20000000
/**
 * δ��ʹ�á�����IPROUTE2�������ip rule������﷨���ڸ���������һ���ؼ���reject�����ùؼ��ֻ�δ�����ܡ�
 */
#define RTCF_REJECT	0x40000000
/**
 * ·�ɵ�Ŀ�ĵ�ַ��һ�����ص�ַ�������ؽӿ������õ�ĳ����ַ����
 * �Ա��ع㲥��ַ�ͱ��ضಥ��ַҲ���øñ�־
 */
#define RTCF_LOCAL	0x80000000

/**
 * ��Щ��־���ٱ�IPv4ʹ�á�������ǰ��FastNAT����ʹ�ã���������2.6�ں����Ѿ���ɾ��
 */
#define RTCF_NAT	(RTCF_DNAT|RTCF_SNAT)

#define RT_TOS(tos)	((tos)&IPTOS_TOS_MASK)

#endif /* _LINUX_IN_ROUTE_H */
