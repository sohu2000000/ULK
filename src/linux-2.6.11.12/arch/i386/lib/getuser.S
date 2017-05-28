/*
 * __get_user functions.
 *
 * (C) Copyright 1998 Linus Torvalds
 *
 * These functions have a non-standard call interface
 * to make them more efficient, especially as they
 * return an error value in addition to the "real"
 * return value.
 */
#include <asm/thread_info.h>


/*
 * __get_user_X
 *
 * Inputs:	%eax contains the address
 *
 * Outputs:	%eax is error code (0 or -EFAULT)
 *		%edx contains zero-extended value
 *
 * These functions should not modify any other registers,
 * as they get called from within inline assembly.
 */

.text
.align 4
.globl __get_user_1
__get_user_1:
	GET_THREAD_INFO(%edx)
	cmpl TI_addr_limit(%edx),%eax
	jae bad_get_user
1:	movzbl (%eax),%edx
	xorl %eax,%eax
	ret

.align 4
.globl __get_user_2
__get_user_2:
    /*
     * eax寄存器包含要读取的第一个字节的地址ptr
	 */
	addl $1,%eax
	jc bad_get_user
	/*
	 * 检查并确定要读取的两个字节的地址小于4GB并小于current进程的addr_limit.seg字段
	 */
	GET_THREAD_INFO(%edx)
	cmpl TI_addr_limit(%edx),%eax
	jae bad_get_user
	/*
	 * 如果地址有效，就执行movzwl，把读取的数据保存到edx寄存器的两个低字节，而且把两个高字节置位0，然后再eax中设置返回码0并终止
	 */
2:	movzwl -1(%eax),%edx
	xorl %eax,%eax
	ret

.align 4
.globl __get_user_4
__get_user_4:
	addl $3,%eax
	jc bad_get_user
	GET_THREAD_INFO(%edx)
	cmpl TI_addr_limit(%edx),%eax
	jae bad_get_user
3:	movl -3(%eax),%edx
	xorl %eax,%eax
	ret

bad_get_user:
    /*
     * 如果地址无效，函数清edx，将eax设置为-EFAULT并终止
	 */
	xorl %edx,%edx
	movl $-14,%eax
	ret

/*
 * 对于前面的__get_user_1，__get_user_2，__get_user_4产生的异常，修复代码为bad_get_user，并将这三个表项加入异常表
 * GNU 汇编程序伪指令.section允许程序员指定可执行文件的哪部分包含紧接着要执行的代码。
 * 可执行文件包括一个代码段，这个代码段可能又依次划分为节
 * .previous伪指令强制程序把紧接着的代码插入到遇到一个.section伪指令时激活的节
 */
.section __ex_table,"a"
	.long 1b,bad_get_user
	.long 2b,bad_get_user
	.long 3b,bad_get_user
.previous
