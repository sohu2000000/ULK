/*
 * mm/thrash.c
 *
 * Copyright (C) 2004, Red Hat, Inc.
 * Copyright (C) 2004, Rik van Riel <riel@redhat.com>
 * Released under the GPL, see the file COPYING for details.
 *
 * Simple token based thrashing protection, using the algorithm
 * described in:  http://www.cs.wm.edu/~sjiang/token.pdf
 */
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/swap.h>

static DEFINE_SPINLOCK(swap_token_lock);
static unsigned long swap_token_timeout;
unsigned long swap_token_check;
/*
 * ������ǵľ���������ʽ��swap_token_mm�ڴ�������ָ�롣������ӵ�н������ʱ��swap_token_mm������Ϊ�����ڴ��������ĵ�ַ
 */
struct mm_struct * swap_token_mm = &init_mm;

#define SWAP_TOKEN_CHECK_INTERVAL (HZ * 2)
#define SWAP_TOKEN_TIMEOUT	0
/*
 * Currently disabled; Needs further code to work at HZ * 300.
 */
unsigned long swap_token_default_timeout = SWAP_TOKEN_TIMEOUT;

/*
 * Take the token away if the process had no page faults
 * in the last interval, or if it has held the token for
 * too long.
 */
#define SWAP_TOKEN_ENOUGH_RSS 1
#define SWAP_TOKEN_TIMED_OUT 2
static int should_release_swap_token(struct mm_struct *mm)
{
	int ret = 0;
    /*
     * ��ǰӵ�н�����ǵĽ���û���ٴ����ȱҳ
     */
	if (!mm->recent_pagein)
		ret = SWAP_TOKEN_ENOUGH_RSS;
    /*
     * ��ǰӵ�н�����ǵĽ��̵�ʱ�䳬����swap_token_default_timeout
     */
	else if (time_after(jiffies, swap_token_timeout))
		ret = SWAP_TOKEN_TIMED_OUT;
    /*
     * ȥ����ǰӵ�н�����ǽ��̽��̵��ٴη���ȱҳ�ı��
     */
	mm->recent_pagein = 0;
	return ret;
}

/*
 * Try to grab the swapout protection token.  We only try to
 * grab it once every TOKEN_CHECK_INTERVAL, both to prevent
 * SMP lock contention and to check that the process that held
 * the token before is no longer thrashing.
 */
/**
 * �����Ƿ񽫽�����Ǹ�����ǰ���̡�����ȱҳʱ����:
 *		��filemap_nopage������������ҳ����ҳ���ٻ�����ʱ��
 *		��do_swap_page�����ӽ���������һ����ҳʱ��
 */
void grab_swap_token(void)
{
	struct mm_struct *mm;
	int reason;

	/* We have the token. Let others know we still need it. */
	/**
	 * �Ѿ��н�������ˣ�����������ȱҳ��Ǿ����ˡ�
	 * recent_pagein = 1˵���������ڻ�ý�����ǲ��ú����ٴη�����ȱҳ(��Ϊ������ֻ����ȱҳʱ�򱻵���)
	 */
	if (has_swap_token(current->mm)) {
		current->mm->recent_pagein = 1;
		return;
	}

	/**
	 * �Դ��ϴ����ý�������������Ѿ��������롣
	 */
	if (time_after(jiffies, swap_token_check)) {

		/* Can't get swapout protection if we exceed our RSS limit. */
		// if (current->mm->rss > current->mm->rlimit_rss)
		//	return;

		/* ... or if we recently held the token. */
		/**
		 * �ϴε��ú󣬵�ǰӵ�н�����ǵĽ������û���ٻ�ñ�ǡ�
		 */
		if (time_before(jiffies, current->mm->swap_token_time))
			return;

		if (!spin_trylock(&swap_token_lock))
			return;

		swap_token_check = jiffies + SWAP_TOKEN_CHECK_INTERVAL;

        /*
         * �õ���ǰӵ�н�����ǽ��̵Ľ���������
         */
		mm = swap_token_mm;

        /*
         * �������������Ÿ��轻�����
         *  ��ǰӵ�н�����ǵĽ���û���ٴ����ȱҳ
         *  ��ǰӵ�н�����ǵĽ��̵�ʱ�䳬����swap_token_default_timeout
         */        
		if ((reason = should_release_swap_token(mm))) {
			unsigned long eligible = jiffies;
			if (reason == SWAP_TOKEN_TIMED_OUT) {
				eligible += swap_token_default_timeout;
			}
			mm->swap_token_time = eligible;
			swap_token_timeout = jiffies + swap_token_default_timeout;
            /*
             * ��������Ǹ�����ǰ����
             */
			swap_token_mm = current->mm;
		}
		spin_unlock(&swap_token_lock);
	}
	return;
}

/* Called on process exit. */
void __put_swap_token(struct mm_struct *mm)
{
	spin_lock(&swap_token_lock);
	if (likely(mm == swap_token_mm)) {
		swap_token_mm = &init_mm;
		swap_token_check = jiffies;
	}
	spin_unlock(&swap_token_lock);
}
