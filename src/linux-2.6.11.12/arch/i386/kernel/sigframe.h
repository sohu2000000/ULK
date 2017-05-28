/**
 * �����û�̬�źŴ�����ʱ�����û�̬ջ֡�б��������
 */
struct sigframe
{
	/**
	 * �źŴ������ķ��ص�ַ����ָ��__kernel_sigreturn��Ǵ��Ĵ��롣
	 * ��Ȼ����δ��������û�ִ̬�еġ�
	 * xie.baoyouע��linux����ν�__kernel_sigreturn�ĵ�ַ���û�̬����ʶ�𵽵��أ���
	 */
	char *pretcode;
	/**
	 * �źű�ţ��źŴ�������Ҫ�������
	 */
	int sig;
	/**
	 * �������л����ں�̬ǰ���û�̬����Ӳ�������ġ�
	 * ע�⣺�ǵ�һ�ν����ں�̬ʱ���û�̬��Ӳ�������ģ������û�̬�������Ū���������Ҳ���£�������û�̬���������
	 * ������Ӱ���ں˵��ȶ��ԡ�
	 * ��Ҳ�Ǳ������쳣���жϷ����û�̬ǰ�Ŵ����źŵ�ԭ��֮һ�������������ط���
	 * �����źŴ�������С���ˣ���Ҫ��ջŪ���ˣ�����Ӧ�ó��������ִ�����̿��ܱ��ƻ���
	 */
	struct sigcontext sc;
	/**
	 * ����û�̬���̵ĸ���Ĵ��������ݡ�
	 */
	struct _fpstate fpstate;
	/**
	 * ��������ʵʱ�ź�λͼ��
	 */
	unsigned long extramask[_NSIG_WORDS-1];
	/**
	 * ����sigreturnϵͳ���õ�8�ֽڴ��롣�����ڰ汾�У��������á�����2.6�У�����������һ�������ʹ�á�
	 * �Ա���Գ����ܹ�ʶ����ź�ջ֡��
	 */
	char retcode[8];
};

struct rt_sigframe
{
	char *pretcode;
	int sig;
	struct siginfo *pinfo;
	void *puc;
	struct siginfo info;
	struct ucontext uc;
	struct _fpstate fpstate;
	char retcode[8];
};
