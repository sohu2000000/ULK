/*
 * linux/kernel/irq/handle.c
 *
 * Copyright (C) 1992, 1998-2004 Linus Torvalds, Ingo Molnar
 *
 * This file contains the core interrupt handling code.
 */

#include <linux/irq.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>

#include "internals.h"

/*
 * Linux has a controller-independent interrupt architecture.
 * Every controller has a 'controller-template', that is used
 * by the main code to do the right thing. Each driver-visible
 * interrupt source is transparently wired to the apropriate
 * controller. Thus drivers need not be aware of the
 * interrupt-controller.
 *
 * The code is designed to be easily extended with new/different
 * interrupt controllers, without having to do assembly magic or
 * having to touch the generic code.
 *
 * Controller mappings for all interrupt sources:
 */
irq_desc_t irq_desc[NR_IRQS] __cacheline_aligned = {
	[0 ... NR_IRQS-1] = {
		.handler = &no_irq_type,
		.lock = SPIN_LOCK_UNLOCKED
	}
};

/*
 * Generic 'no controller' code
 */
static void end_none(unsigned int irq) { }
static void enable_none(unsigned int irq) { }
static void disable_none(unsigned int irq) { }
static void shutdown_none(unsigned int irq) { }
static unsigned int startup_none(unsigned int irq) { return 0; }

static void ack_none(unsigned int irq)
{
	/*
	 * 'what should we do if we get a hw irq event on an illegal vector'.
	 * each architecture has to answer this themself.
	 */
	ack_bad_irq(irq);
}

struct hw_interrupt_type no_irq_type = {
	.typename = 	"none",
	.startup = 	startup_none,
	.shutdown = 	shutdown_none,
	.enable = 	enable_none,
	.disable = 	disable_none,
	.ack = 		ack_none,
	.end = 		end_none,
	.set_affinity = NULL
};

/*
 * Special, empty irq handler:
 */
irqreturn_t no_action(int cpl, void *dev_id, struct pt_regs *regs)
{
	return IRQ_NONE;
}

/*
 * Have got an event to handle:
 */
/**
 * ִ���жϷ�������
 */
fastcall int handle_IRQ_event(unsigned int irq, struct pt_regs *regs,
				struct irqaction *action)
{
	int ret, retval = 0, status = 0;

	/**
	 * ���û������SA_INTERRUPT��˵���жϴ�������ǿ����ڿ��ж������ִ�е�
	 * ��Ҳ�ǳ������ټ��ģ�����local_irq_enable�ĵط���
	 * һ����˵������local_irq_enable��Σ�յģ�������������������ֻ�����⡣
	 */
	if (!(action->flags & SA_INTERRUPT))
		local_irq_enable();

	/**
	 * һ��ʼ��action��irqaction�����ͷ��irqaction��ʾһ��ISR
	 */
	do {
		/**
		 * handler���жϷ������̵Ĵ�����������������������
		 * irq-IRQ�ţ�������һ��ISR������IRQ��
		 * dev_id-�豸�ţ�ע���жϷ�������ʱָ������ʱ�ش�����������������һ��ISR������ͬ���͵��豸��
		 * regs-ָ���ں�ջ��pt_regs��������ISR�����ں�ִ�������ġ����ǣ��ĸ�ISR�������أ�
		 */
		ret = action->handler(irq, action->dev_id, regs);
		if (ret == IRQ_HANDLED)
			status |= action->flags;
		/**
		 * һ����˵��handler�����˱����жϣ��ͻ᷵��1
		 * ����0��1�����õģ������������ں��ж��ж��Ƿ񱻴����ˡ�
		 * ���������ж�û�б�������˵��Ӳ�������⣬������α�жϡ�
		 */
		retval |= ret;
		action = action->next;
	} while (action);

	/**
	 * ����ж���������Ĳ���Դ�������һ��������ӡ�
	 */
	if (status & SA_SAMPLE_RANDOM)
		add_interrupt_randomness(irq);

	/**
	 * �˳�ʱ�����ǻ���жϣ����ﲻ�ж�if (!(action->flags & SA_INTERRUPT))
	 * ����Ϊ���жϵĻ��ָ���ֱ��ִ��cli��ʱ����Ȼ������ζ�����Ҫ��֤���ڹ��ж�״̬��Ϊʲô������Щ�ж��ء�
	 */
	local_irq_disable();

	return retval;
}

/*
 * do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 */
fastcall unsigned int __do_IRQ(unsigned int irq, struct pt_regs *regs)
{
	irq_desc_t *desc = irq_desc + irq;
	struct irqaction * action;
	unsigned int status;

	/**
	 * �жϷ�����������.
	 */
	kstat_this_cpu.irqs[irq]++;
	if (desc->status & IRQ_PER_CPU) {
		irqreturn_t action_ret;

		/*
		 * No locking required for CPU-local interrupts:
		 */
		desc->handler->ack(irq);
		action_ret = handle_IRQ_event(irq, regs, desc->action);
		if (!noirqdebug)
			note_interrupt(irq, desc, action_ret);
		desc->handler->end(irq);
		return 1;
	}

	/**
	 * ��Ȼ�ж��ǹرյ�,���ǻ�����Ҫʹ������������desc
	 */
	spin_lock(&desc->lock);
	/**
	 * ����Ǿɵ�8259A PIC,ack����mask_and_ack_8259A,��Ӧ��PIC�ϵ��жϲ���������IRQ��.����IRQ����Ϊ��ȷ��������жϴ���������ǰ,
	 * CPU����һ�����������жϵĳ���.
	 * do_IRQ���Խ�ֹ�����ж�����,��ʵ��,CPU���Ƶ�Ԫ�Զ���eflags�Ĵ�����IF��־.��Ϊ�жϴ��������ͨ��IDT�ж��ŵ��õ�.
	 * ����,�ں���ִ������жϵ��жϷ�������֮ǰ���ܻ����¼�����ж�.
	 * ��ʹ��APICʱ,Ӧ���ж��������ж�����,������ack,Ҳ�����ӳٵ��жϴ���������(Ҳ����Ӧ����end����ȥ��).
	 * �������,�жϴ���������ǰ,����APIC����һ�����������ж�,���������жϿ��ܻᱻ����CPU����.
	 */
	desc->handler->ack(irq);
	/*
	 * REPLAY is when Linux resends an IRQ that was dropped earlier
	 * WAITING is used by probe to mark irqs that are being tested
	 */
	/**
	 * ��ʼ����IRQ�������ļ�����־.����IRQ_PENDING��־.Ҳ���IRQ_WAITING��IRQ_REPLAY
	 * �⼸����־���ԺܺõĽ���ж����������.
	 * IRQ_REPLAY��־��"��ȶ�ʧ���ж�"����.�ڴ˲�����.
	 */
	status = desc->status & ~(IRQ_REPLAY | IRQ_WAITING);
	status |= IRQ_PENDING; /* we _want_ to handle it */

	/*
	 * If the IRQ is disabled for whatever reason, we cannot
	 * use the action we have.
	 */
	action = NULL;
	/**
	 * IRQ_DISABLED��IRQ_INPROGRESS������ʱ,ʲô������(action==NULL)
	 * ��ʹIRQ�߱���ֹ,CPUҲ����ִ��do_IRQ����.����,��������Ϊ��ȶ�ʧ���ж�,���,Ҳ��������������������α�ж�.
	 * ����,�Ƿ����ִ���жϴ���,��Ҫ����IRQ_DISABLED��־���ж�,���������ǽ���IRQ��.
	 * IRQ_INPROGRESS��־��������:���һ��CPU���ڴ���һ���ж�,��ô������������IRQ_INPROGRESS.����,����CPU�Ϸ���ͬ�����ж�
	 * �Ϳ��Լ���Ƿ�������CPU�����ڴ���ͬ�����͵��ж�,�����,��ʲô������,�����������ºô�:
	 * һ��ʹ�ں˽ṹ��,����������жϷ�������ʽ�����ǿ������.���ǿ��Ա���Ū�൱ǰCPU��Ӳ�����ٻ���.
	 */
	if (likely(!(status & (IRQ_DISABLED | IRQ_INPROGRESS)))) {
		action = desc->action;
		/*
		 * ȷ������Ҫ�����ˣ�������IRQ_INPROGRESS ��־��
		 * ȥ��IRQ_PENDING ��־��ʾȷ������Ҫ��������ж���
		 */
		status &= ~IRQ_PENDING; /* we commit to handling */
		status |= IRQ_INPROGRESS; /* we are handling it */
	}
	desc->status = status;

	/*
	 * If there is no IRQ handler or it was disabled, exit early.
	 * Since we set PENDING, if another processor is handling
	 * a different instance of this same irq, the other processor
	 * will take care of it.
	 */
	/**
	 * ��ǰ�������������ʱ,����Ҫ(�����ǲ���Ҫ����)�����ж�.���˳�
	 * ����û����ص��жϷ�������ʱ,Ҳ�˳�.���ں����ڼ��Ӳ���豸ʱ�ͻᷢ���������.
	 */
	if (unlikely(!action))
		goto out;

	/*
	 * Edge triggered interrupts need to remember
	 * pending events.
	 * This applies to any hw interrupts that allow a second
	 * instance of the same irq to arrive while we are in do_IRQ
	 * or in the handler. But the code here only handles the _second_
	 * instance of the irq, not the third or fourth. So it is mostly
	 * useful for irq hardware that does not mask cleanly in an
	 * SMP environment.
	 */
	/**
	 * ��������Ҫѭ�������,������˵����һ��handle_IRQ_event������.
	 */
	for (;;) {
		irqreturn_t action_ret;

		/**
		 * ���ڴ���������,��ô,����CPU����Ҳ���յ�ͬ���ж�,������IRQ_PENDING��־.
		 * xie.baoyouע:��ע�⿪������ʹ�÷���.�е�����,�����Դ�.
		 */
		spin_unlock(&desc->lock);

		/**
		 * �����жϷ�������.
		 */
		action_ret = handle_IRQ_event(irq, regs, action);

		spin_lock(&desc->lock);
		if (!noirqdebug)
			note_interrupt(irq, desc, action_ret);
		/**
		 * �������CPUû�н��յ�ͬ���ж�,���˳�
		 * ����,��������ͬ���ж�.
		 */
		if (likely(!(desc->status & IRQ_PENDING)))
			break;
		/**
		 * �����IRQ_PENDING,����ٳ���IRQ_PENDING,��˵��������CPU�Ͻ��յ���ͬ���ж�.
		 * ע��,IRQ_PENDING������һ����־,����ڵ����жϴ������Ĺ�����,���˶�ε�ͬ���ж�,����ζ��ֻ��һ�α�����,����Ķ���ʧ��.
		 */
		desc->status &= ~IRQ_PENDING;
	}
	desc->status &= ~IRQ_INPROGRESS;

out:
	/*
	 * The ->end() handler has to deal with interrupts which got
	 * disabled while the handler was running.
	 */
	/**
	 * ����׼���˳���,end����������Ӧ���ж�(APIC),Ҳ������ͨ��end_8259A_irq�������¼���IRQ(ֻҪ����α�ж�).
	 */
	desc->handler->end(irq);
	/**
	 * ��,�����Ѿ�ȫ�������,�ͷ���������.ע�������������ʹ�÷���.
	 */
	spin_unlock(&desc->lock);

	return 1;
}

