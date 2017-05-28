/*
 * NFS protocol definitions
 *
 * This file contains constants for Version 2 of the protocol.
 */
#ifndef _LINUX_NFS2_H
#define _LINUX_NFS2_H

#define NFS2_PORT	2049
#define NFS2_MAXDATA	8192
#define NFS2_MAXPATHLEN	1024
#define NFS2_MAXNAMLEN	255
#define NFS2_MAXGROUPS	16
#define NFS2_FHSIZE	32
#define NFS2_COOKIESIZE	4
#define NFS2_FIFO_DEV	(-1)
#define NFS2MODE_FMT	0170000
#define NFS2MODE_DIR	0040000
#define NFS2MODE_CHR	0020000
#define NFS2MODE_BLK	0060000
#define NFS2MODE_REG	0100000
#define NFS2MODE_LNK	0120000
#define NFS2MODE_SOCK	0140000
#define NFS2MODE_FIFO	0010000


/* NFSv2 file types - beware, these are not the same in NFSv3 */
enum nfs2_ftype {
	NF2NON = 0,
	NF2REG = 1,
	NF2DIR = 2,
	NF2BLK = 3,
	NF2CHR = 4,
	NF2LNK = 5,
	NF2SOCK = 6,
	NF2BAD = 7,
	NF2FIFO = 8
};

struct nfs2_fh {
	char			data[NFS2_FHSIZE];
};

/*
 * Procedure numbers for NFSv2
 */
/**
 * NFS����š�
 */
#define NFS2_VERSION		2
/**
 * ����ϰ�ߣ����κ�RPC�����й���0����Ϊ�գ���Ϊ��û���κζ�����
 * Ӧ�ó�����Ե�����������ĳ���������Ƿ���Ӧ��
 */
#define NFSPROC_NULL		0
/**
 * �ͻ������ù���1���õ�ĳ���ļ������ԣ���������ģʽ���ļ�ӵ���ߡ���С�Լ������ȡʱ����
 */
#define NFSPROC_GETATTR		1
/**
 * ����2����ͻ��������ļ���ĳЩ���ԡ��ͻ������������������ԣ�����fsid��rdev��fileid�ȣ���������óɹ������᷵�ظı���ļ������ԡ�
 */
#define NFSPROC_SETATTR		2
/**
 * �˹�����NFS3���Ѿ������ڣ�����װЭ��ȡ����
 */
#define NFSPROC_ROOT		3
/**
 * �˹�����һ��Ŀ¼������ĳ���ļ�������ɹ����򷵻ص�ֵ�ɸ��ļ������Լ�������ɡ�
 */
#define NFSPROC_LOOKUP		4
/**
 * ����ͻ����ѷ������ӵ�ֵ��������
 */
#define NFSPROC_READLINK	5
/**
 * ����ͻ�����ĳ���ļ��ж������ݡ���������������ɹ������ؽ������������Ҫ�����ݼ����ļ������ԣ��������ʧ�ܣ���״ֵ̬������һ�������롣
 */
#define NFSPROC_READ		6
/**
 * �˹�����NFS3���Ѿ������ڡ�
 */
#define NFSPROC_WRITECACHE	7
/**
 * ����ͻ���һ��Զ���ļ�д�����ݡ����óɹ������ļ������ԣ��������һ��������롣
 */
#define NFSPROC_WRITE		8
/**
 * �ͻ������ù���9��һ��ָ��Ŀ¼����һ���ļ������ļ����ܴ��ڣ�����õ��ý����ز����������ɹ������������ļ��ľ���������ԡ�
 */
#define NFSPROC_CREATE		9
/**
 * �ͻ������ù���10��ɾ��һ���Ѿ����ڵ��ļ����õ��÷���һ��״ֵ̬����״ֵָ̬ʾ�˲����Ƿ�ɹ���
 */
#define NFSPROC_REMOVE		10
/**
 * �ͻ������ù���11Ϊһ���ļ����������ڲ���ʹ�ͻ�������ָ���ļ����µ����ֺ��µ�Ŀ¼������rename�����Ͷ�Ӧ��UNIXC��mv���NFS��֤rename�ڷ���������ԭ�Ӳ�����Ҳ����˵������ִ�в��ᱻ�жϣ�����ԭ���Եı�֤ʮ����Ҫ����Ϊ����ζ��֪����װ���ļ����������ܰѾ���ɾ����
 */
#define NFSPROC_RENAME		11
/**
 * ����12����ͻ����γ�һ�����Ѵ����ļ���Ӳ���ӡ�NFS��֤�����һ���ļ��ж�����ӣ���ô�������������ӶԸ��ļ����д�ȡ���ļ��Ŀ������Զ���һ�µġ�
 */
#define NFSPROC_LINK		12
/**
 * ����13����һ���������ӡ�����ָ����һ��Ŀ¼�����Ҫ�������ļ����Լ���Ϊ�÷����������ݵ��ַ�����
 */
#define NFSPROC_SYMLINK		13
/**
 * ����14����һ��Ŀ¼��������óɹ����������������Ŀ¼�ľ���������ԡ�
 */
#define NFSPROC_MKDIR		14
/**
 * �ͻ������ù���15��ɾ��һ��Ŀ¼��������UNIX��һ����һ��Ŀ¼��ɾ����ǰ�����ǿյġ�
 */
#define NFSPROC_RMDIR		15
/**
 * �ͻ������ù���16��һ��Ŀ¼�ж�ȡ���е�Ŀ¼�
 */
#define NFSPROC_READDIR		16
/**
 * ����17����ͻ����õ�פ����ĳ���ļ����ļ�ϵͳ����Ϣ��
 * ���ؽ������������Ϣ��ָ�����Ŵ����С������read��write�����е����ݳ��ȣ�������ȿ��Բ������ŵĴ����ʣ����洢�豸�����ݿ��С���豸�Ŀ�������ǰδʹ�õĿ����Լ�����Ȩ�û����õ�δʹ�ÿ�����
 */
#define NFSPROC_STATFS		17

#define NFS_MNT_PROGRAM		100005
#define NFS_MNT_VERSION		1
#define MNTPROC_NULL		0
#define MNTPROC_MNT		1
#define MNTPROC_UMNT		3
#define MNTPROC_UMNTALL		4

#endif /* _LINUX_NFS2_H */
