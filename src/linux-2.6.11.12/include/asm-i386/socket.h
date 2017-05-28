#ifndef _ASM_SOCKET_H
#define _ASM_SOCKET_H

#include <asm/sockios.h>

/* For setsockopt(2) */
#define SOL_SOCKET	1

/**
 * ʹ�ܴ�ѡ�������ģ������SOCK_DEBUG������Ļ������־���������Ϣ��
 */
#define SO_DEBUG	1
/**
 * ���������׽ӿڸ��õ�ַ�Ͷ˿ڡ�
 * Ҫ�������׽ӿڶ����ô�ѡ����ߵڶ����׽ӿ����ô�ѡ�����1.
 */
#define SO_REUSEADDR	2
/**
 * �Ӵ�����ƿ��л���׽ӿڵ����ͣ���SOCK_DGRAM��SOCK_STREAM��
 */
#define SO_TYPE		3
/**
 * �Ӵ�����ƿ��л�ô����롣���ȴ�sk_err�л�ã����Ϊ0���ٴ�sk_err_soft�л�ô����롣
 * 0��ʾû�д���
 */
#define SO_ERROR	4
/**
 * ����Ҫ��ѯ·�ɱ�ֱ�ӴӰ󶨵Ľӿڽ����ݷ��ͳ�ȥ��
 * ��ѡ���ֵ�����ڴ�����ƿ��SOCK_LOCALROUTE��־λ�С�
 */
#define SO_DONTROUTE	5
/**
 * ��ʾ�׽ӿ��Ѿ����ó��շ��㲥��Ϣ����ѡ������Է�SOCK_STREAM���͵��׽ӿ���Ч��
 */
#define SO_BROADCAST	6
/**
 * ���÷��ͻ�������С�����ܴ���sysctl_wmem_max��
 * ��������ã���Ĭ�ϻ�������СΪtcp_wmem[1]
 */
#define SO_SNDBUF	7
/**
 * ���ý��ջ�������С��
 */
#define SO_RCVBUF	8
/**
 * �Ƿ���������ܡ�
 * �����ڴ�����ƿ��SOCK_KEEPOPEN��־�С�
 */
#define SO_KEEPALIVE	9
/**
 * ������������ͨ������һ��
 * ������ֵ������SOCK_URGINLINE��־�С�
 */
#define SO_OOBINLINE	10
/**
 * ���ھ���RAW��UDP�Ƿ����У��͡�������sk_no_check��Ա�С�
 */
#define SO_NO_CHECK	11
/**
 * ���÷��ͻ���ת������QoS���ѡ��ֵ������sk_priorit��Ա�С���ֵ�������0-6֮�䡣
 */
#define SO_PRIORITY	12
/**
 * ���û��߻�ȡ�׽ӿڵ��ӳ�ʱ��ֵ��
 */
#define SO_LINGER	13
/**
 * �Ѿ�����
 */
#define SO_BSDCOMPAT	14
/* To add :#define SO_REUSEPORT 15 */
/**
 * ��Ҫ����PF_UNIXЭ����
 */
#define SO_PASSCRED	16
#define SO_PEERCRED	17
/**
 * ���ջ�������ֵ�������ڴ�����ƿ��sk_rcvlowat��Ա�С�
 */
#define SO_RCVLOWAT	18
/**
 * ���ͻ�������ֵ��ʼ��Ϊ1.
 */
#define SO_SNDLOWAT	19
/**
 * ���û��߻�ȡ���ճ�ʱֵ���Ժ���Ϊ��λ��
 * ������sk_rcvtimeo��Ա�С�
 */
#define SO_RCVTIMEO	20
/**
 * ���ͳ�ʱֵ���Ժ���Ϊ��λ��
 * ������sk_sndtimeo��Ա�С�
 */
#define SO_SNDTIMEO	21

/* Security levels - as per NRL IPv6 - don't actually do anything */
#define SO_SECURITY_AUTHENTICATION		22
#define SO_SECURITY_ENCRYPTION_TRANSPORT	23
#define SO_SECURITY_ENCRYPTION_NETWORK		24

/**
 * ���׽ӿڰ󶨵�ָ���豸�ϡ�
 * ������sk_bound_def_if��Ա�С�
 */
#define SO_BINDTODEVICE	25

/* Socket filtering */
/**
 * װ�ء�ж���׽ӿڵĹ�������
 */
#define SO_ATTACH_FILTER        26
#define SO_DETACH_FILTER        27

/**
 * ��ȡ�Զ˵ĵ�ַ�Ͷ˿ڡ�������daddr��dport�С�
 */
#define SO_PEERNAME		28
/**
 * ���ΪTRUE����ô�����ݰ�����ʱ����Ϊʱ�����
 * ������SOCK_RCVTSTAMP��־λ�С�
 */
#define SO_TIMESTAMP		29
#define SCM_TIMESTAMP		SO_TIMESTAMP

/**
 * �Ƿ���listen״̬��
 */
#define SO_ACCEPTCONN		30

/**
 * �Ӱ�ȫģ���л�ȡ��ȫ��֤�������ġ�
 */
#define SO_PEERSEC		31

#endif /* _ASM_SOCKET_H */
