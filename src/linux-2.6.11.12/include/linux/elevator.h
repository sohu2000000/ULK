#ifndef _LINUX_ELEVATOR_H
#define _LINUX_ELEVATOR_H

typedef int (elevator_merge_fn) (request_queue_t *, struct request **,
				 struct bio *);

typedef void (elevator_merge_req_fn) (request_queue_t *, struct request *, struct request *);

typedef void (elevator_merged_fn) (request_queue_t *, struct request *);

typedef struct request *(elevator_next_req_fn) (request_queue_t *);

typedef void (elevator_add_req_fn) (request_queue_t *, struct request *, int);
typedef int (elevator_queue_empty_fn) (request_queue_t *);
typedef void (elevator_remove_req_fn) (request_queue_t *, struct request *);
typedef void (elevator_requeue_req_fn) (request_queue_t *, struct request *);
typedef struct request *(elevator_request_list_fn) (request_queue_t *, struct request *);
typedef void (elevator_completed_req_fn) (request_queue_t *, struct request *);
typedef int (elevator_may_queue_fn) (request_queue_t *, int);

typedef int (elevator_set_req_fn) (request_queue_t *, struct request *, int);
typedef void (elevator_put_req_fn) (request_queue_t *, struct request *);

typedef int (elevator_init_fn) (request_queue_t *, elevator_t *);
typedef void (elevator_exit_fn) (elevator_t *);

/* �����㷨�Ļص����� */
struct elevator_ops
{
	/* ���ҿ��Ժ�bio���кϲ������󣬷�����ELEVATOR_NO_MERGE */
	elevator_merge_fn *elevator_merge_fn;
	/* �ڵ����������󱻺ϲ�ʱ�����á� */
	elevator_merged_fn *elevator_merged_fn;
	/* �ϲ�����ʱ�ص� */
	elevator_merge_req_fn *elevator_merge_req_fn;

	elevator_next_req_fn *elevator_next_req_fn;
	/* �����������������ʱ���� */
	elevator_add_req_fn *elevator_add_req_fn;
	elevator_remove_req_fn *elevator_remove_req_fn;
	elevator_requeue_req_fn *elevator_requeue_req_fn;

	/* �ж϶����Ƿ�Ϊ�� */
	elevator_queue_empty_fn *elevator_queue_empty_fn;
	/* �������ʱ���� */
	elevator_completed_req_fn *elevator_completed_req_fn;

	elevator_request_list_fn *elevator_former_req_fn;
	elevator_request_list_fn *elevator_latter_req_fn;

	/* ��ĳЩ�����㷨����Ϊ�������洢�ռ� */
	elevator_set_req_fn *elevator_set_req_fn;
	/* ��ĳЩ�����㷨����Ϊ�����ͷŴ洢�ռ� */
	elevator_put_req_fn *elevator_put_req_fn;

	/* ���������ϣ�����е�ǰ�����Ľ�һ���µ������������ʱ���ã���ʱ���ܶ����Ƿ񳬹����� */
	elevator_may_queue_fn *elevator_may_queue_fn;

	/* ��ʼ��������Ϊ�㷨�����ض����ڴ� */
	elevator_init_fn *elevator_init_fn;
	/* �ͷź������ͷ��ض����ڴ� */
	elevator_exit_fn *elevator_exit_fn;
};

#define ELV_NAME_MAX	(16)

/*
 * identifies an elevator type, such as AS or deadline
 */
/* IO�����㷨������ */
struct elevator_type
{
	/* ͨ�����ֶμ��뵽�����㷨��������dlv_list�� */
	struct list_head list;
	/* �����㷨�Ļص����� */
	struct elevator_ops ops;
	struct elevator_type *elevator_type;
	/* ����ģ��ʹ�� */
	struct kobj_type *elevator_ktype;
	/* �㷨���� */
	char elevator_name[ELV_NAME_MAX];
	/* ����ģ�� */
	struct module *elevator_owner;
};

/*
 * each queue has an elevator_queue assoicated with it
 */
/* ����IO���ȶ��� */
struct elevator_queue
{
	/* �����������ص� */
	struct elevator_ops *ops;
	/* ���ȶ���˽�����ݣ���������޵����㷨��deadline_data */
	void *elevator_data;
	/* ����ģ��ʹ�� */
	struct kobject kobj;
	/* �㷨���� */
	struct elevator_type *elevator_type;
};

/*
 * block elevator interface
 */
extern void elv_add_request(request_queue_t *, struct request *, int, int);
extern void __elv_add_request(request_queue_t *, struct request *, int, int);
extern int elv_merge(request_queue_t *, struct request **, struct bio *);
extern void elv_merge_requests(request_queue_t *, struct request *,
			       struct request *);
extern void elv_merged_request(request_queue_t *, struct request *);
extern void elv_remove_request(request_queue_t *, struct request *);
extern void elv_requeue_request(request_queue_t *, struct request *);
extern int elv_queue_empty(request_queue_t *);
extern struct request *elv_next_request(struct request_queue *q);
extern struct request *elv_former_request(request_queue_t *, struct request *);
extern struct request *elv_latter_request(request_queue_t *, struct request *);
extern int elv_register_queue(request_queue_t *q);
extern void elv_unregister_queue(request_queue_t *q);
extern int elv_may_queue(request_queue_t *, int);
extern void elv_completed_request(request_queue_t *, struct request *);
extern int elv_set_request(request_queue_t *, struct request *, int);
extern void elv_put_request(request_queue_t *, struct request *);

/*
 * io scheduler registration
 */
extern int elv_register(struct elevator_type *);
extern void elv_unregister(struct elevator_type *);

/*
 * io scheduler sysfs switching
 */
extern ssize_t elv_iosched_show(request_queue_t *, char *);
extern ssize_t elv_iosched_store(request_queue_t *, const char *, size_t);

extern int elevator_init(request_queue_t *, char *);
extern void elevator_exit(elevator_t *);
extern int elv_rq_merge_ok(struct request *, struct bio *);
extern int elv_try_merge(struct request *, struct bio *);
extern int elv_try_last_merge(request_queue_t *, struct bio *);

/*
 * Return values from elevator merger
 */
/**
 * elv_merge�����ķ���ֵ
 * �ú�������µ�BIO�����Ƿ���Բ����Ѿ����ڵ������С�
 */
/**
 * �Ѿ����ڵ������в��ܰ���BIO�ṹ��
 */
#define ELEVATOR_NO_MERGE	0
/**
 * BIO�ṹ������Ϊĩβ��BIO�����뵽ĳ�������С���ʱ�����ܻ�����Ƿ�����һ������ϲ���
 */
#define ELEVATOR_FRONT_MERGE	1
/**
 * BIO�ṹ������Ϊĳ������ĵ�һ��BIO�����롣��ʱ��Ҫ����Ƿ��ܹ���ǰһ������ϲ���
 */
#define ELEVATOR_BACK_MERGE	2

/*
 * Insertion selection
 */
#define ELEVATOR_INSERT_FRONT	1
#define ELEVATOR_INSERT_BACK	2
#define ELEVATOR_INSERT_SORT	3

/*
 * return values from elevator_may_queue_fn
 */
enum {
	ELV_MQUEUE_MAY,
	ELV_MQUEUE_NO,
	ELV_MQUEUE_MUST,
};

#endif
