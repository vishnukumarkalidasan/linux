// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include "errors.h"

#include "xmglru.skel.h"

/****timer thread defs***/
timer_t timer_id;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
int counter = 0;
/***********************/

#define MAP_SHIFT (12 + 9)

static bool terminate;

struct args {
	int memcg_id;
};

struct seq_args {
        int memcg_id;
        int swapiness;
        int force_scan;
        int reclaim_nr;
};

struct thread_data {
	struct seq_args seq;
	int age_fd;
	int seq_fd;
};

/*
 * Thread start routine to notify the application when the
 * timer expires. This routine is run "as if" it were a new
 * thread, each time the timer expires.
 *
 * When the timer has expired 5 times, the main thread will
 * be awakened, and will terminate the program.
 */
void timer_thread (void *arg)
{
    int status;
	struct thread_data *tdat = (struct thread_data *) arg;

    printf ("received agefd %d, seqfd %d, memcgid %d\n", tdat->age_fd, tdat->seq_fd, tdat->seq.memcg_id);
	status = pthread_mutex_lock (&mutex);
    if (status != 0)
        err_abort (status, "Lock mutex");

	status = run_aging(tdat->age_fd, tdat->seq.memcg_id);
	if (status)
		printf("error: age %d\n", status);
	else 
		printf("success: age\n");
	
	status = pthread_mutex_unlock (&mutex);
    	if (status != 0)
        	err_abort (status, "Unlock mutex");
	//sleep(0.5);
	/*
	if (++counter % 2 == 0) {	
	status = pthread_mutex_lock (&mutex);
    	if (status != 0)
        	err_abort (status, "Lock mutex");

	status = run_seq_aging(tdat->seq_fd, tdat->seq.memcg_id, tdat->seq.swapiness, tdat->seq.force_scan, tdat->seq.reclaim_nr);
	if (status)
		printf("error: seq age -- %d\n", status);
	else 
		printf("success: seq age --\n");
	
    	status = pthread_mutex_unlock (&mutex);
    	if (status != 0)
        	err_abort (status, "Unlock mutex");
        //status = pthread_cond_signal (&cond);
        //if (status != 0)
         //   err_abort (status, "Signal condition");
    }
	*/
	/*
    
	*/
}


void handle_sigint(int sig)
{
	terminate = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}
int run_seq_aging(int seq_fd, int memcg_id, int swapy, int force_scan, int reclaim_nr){
	struct seq_args ctx = {
		.memcg_id = memcg_id,
		.swapiness = 1,
		.force_scan = 1,
		.reclaim_nr = 50,
	};
	LIBBPF_OPTS(bpf_test_run_opts, tattr, .ctx_in = &ctx,
		    .ctx_size_in = sizeof(ctx));
	return bpf_prog_test_run_opts(seq_fd, &tattr);
}

int run_aging(int aging_fd, int memcg_id)
{
	struct args ctx = {
		.memcg_id = memcg_id,
	};
	LIBBPF_OPTS(bpf_test_run_opts, tattr, .ctx_in = &ctx,
		    .ctx_size_in = sizeof(ctx));
	return bpf_prog_test_run_opts(aging_fd, &tattr);
}

int attach_progs(pid_t pid, struct xmglru_bpf **xmglru_obj, int *aging_fd,
		 int *xmglru_fd, int *handle_seq_fd)
{
	int err;
	int fd;
	int fd_seq;
	struct xmglru_bpf *obj;

	obj = xmglru_bpf__open();
	if (obj == NULL) {
		perror("Error when opening xmglru bpf object\n");
		printf("Error when opening xmglru bpf object");
		return -1;
	}
	obj->bss->target_pid = pid;

	err = xmglru_bpf__load(obj);
	if (err) {
		perror("Error loading xmglru bpf object\n");
		printf("Error loading xmglru bpf object");
		goto cleanup;
	}

	fd = bpf_program__fd(obj->progs.memcg_run_aging);

	fd_seq = bpf_program__fd(obj->progs.memcg_handle_seq);
	err = xmglru_bpf__attach(obj);
	if (err) {
		perror("Error attaching xmglru bpf object\n");
		printf("Error attaching xmglru bpf object");
		goto cleanup;
	}

	*aging_fd = fd;
	*xmglru_fd = bpf_map__fd(obj->maps.xmglru);
	*xmglru_obj = obj;
	*handle_seq_fd = fd_seq;
	return 0;

cleanup:
	xmglru_bpf__destroy(obj);
	return err;
}

int bpf_map_delete_and_get_next_key(int fd, const void *key, void *next_key)
{
	int err = bpf_map_get_next_key(fd, key, next_key);

	bpf_map_delete_elem(fd, key);
	return err;
}

struct region_stat {
	__u16 accesses;
	__s8 mem_type; /* NON_ANON, ANON */
	__s8 node_id;
};

void dump_map(int fd)
{
	__u64 prev_key, key;
	struct region_stat value;
	int err;

	while (bpf_map_delete_and_get_next_key(fd, &prev_key, &key) == 0) {
		err = bpf_map_lookup_elem(fd, &key, &value);
		if (err < 0) {
			/* impossible if we don't have racing deletions */
			exit(-1);
		}
		printf("%llu %u %d %d\n", key << MAP_SHIFT, value.accesses,
		       value.mem_type, value.node_id);
		prev_key = key;
	}
}

void detach_progs(struct xmglru_bpf *xmglru_obj)
{
	xmglru_bpf__detach(xmglru_obj);
	xmglru_bpf__destroy(xmglru_obj);
}

int start_progs(struct seq_args seq, int interval,int aging_fd) {
		printf("sample start \n");

}

int main(void)
{
	struct xmglru_bpf *xmglru_obj = NULL;
	int aging_fd = -1;
	int xmglru_fd = -1;
	int handle_seq_fd = -1;
	int memcg_id = -1;
	int err;
	int status;
    //struct itimerspec ts;
    //struct sigevent se;
	int timer_start = 0;
	struct seq_args seq;
	struct thread_data tdat;

	signal(SIGINT, handle_sigint);
	setvbuf(stdout, NULL, _IONBF, BUFSIZ);
	libbpf_set_print(libbpf_print_fn);

	while (!terminate) {
/*
		if (timer_start) {
			status = pthread_cond_wait (&cond, &mutex);
        		if (status != 0)
            			printf("error: Wait on condition\n");
			err = run_aging(aging_fd, memcg_id);
			if (err)
				printf("error: age %d\n", err);
			else
				printf("aging success \n");
			
			err = run_seq_aging(handle_seq_fd, memcg_id);
			if (err)
				printf("error: age sequential %d\n", err);
			else
				printf("seq aging success\n");
		}
		*/
		char *buffer = NULL;

		if (scanf("%ms", &buffer) == 1) {
			if (strcmp(buffer, "exit") == 0) {
				printf("No hard feelings.\n");
				exit(0);

			} else if (xmglru_obj == NULL &&
				   strcmp(buffer, "attach") == 0) {
				pid_t pid_;
				int memcg_id_;

				if (scanf("%d %d", &pid_, &memcg_id_) == 2) {
					err = attach_progs(pid_, &xmglru_obj,
							   &aging_fd,
							   &xmglru_fd, &handle_seq_fd);
					if (err) {
						printf("error: aging %d\n",
						       err);
						goto next;
					}
					memcg_id = memcg_id_;
					printf("success: attach\n");

				} else
					printf("error: invalid arguments\n");

			} else if (xmglru_obj != NULL &&
				   strcmp(buffer, "start") == 0) {
					//dump_map(xmglru_fd);
					//printf("success: map\n");

					pid_t pid_;
					int memcg_id_;
					int swapiness_;
        			int force_scan_;
        			int reclaim_nr_;
					int status;
    				struct itimerspec ts;
    				struct sigevent se;
					int interval_;
					

					printf("enter below data in same format:\n memcgid swapiness force_scan reclaim_nr\n\n");

				if (scanf("%d %d %d %d", &memcg_id_, &swapiness_, &force_scan_, &reclaim_nr_) == 4) {
					printf("enter scan interval in similar format:\n msec \n");
					if (scanf("%d", &interval_) == 1) {
 
						tdat.seq.memcg_id = memcg_id_;
						tdat.seq.swapiness = swapiness_;
						tdat.seq.force_scan = force_scan_;
						tdat.seq.reclaim_nr = reclaim_nr_;

						tdat.age_fd = aging_fd;
						tdat.seq_fd = handle_seq_fd;
						

						se.sigev_notify = SIGEV_THREAD;
						se.sigev_value.sival_ptr = &tdat;
						se.sigev_notify_function = timer_thread;
						se.sigev_notify_attributes = NULL;

						/*
						* Specify a repeating timer that fires each 5 seconds.
						*/
						ts.it_value.tv_sec = interval_ / 1000;
						ts.it_value.tv_nsec = (interval_ % 1000) * 1000000;
						ts.it_interval.tv_sec = interval_ / 1000;
						ts.it_interval.tv_nsec = (interval_ % 1000) * 1000000;

    					printf("Creating timer\n");
    					status = timer_create(CLOCK_REALTIME, &se, &timer_id);
    					if (status == -1)
        					printf("Create timer failed\n");
						else {
							status = timer_settime(timer_id, 0, &ts, 0);
    						if (status == -1)
        						printf("Set timer failed\n");
							else {
								timer_start = 1;
							}
						}
						/*
						err = start_progs(seq, interval_,
							   aging_fd);
						if (err) {
							printf("error: aging %d\n",
						       err);
							goto next;
						}
						*/
						memcg_id = memcg_id_;
						printf("success: thread started\n");
					} else
						printf("error: invalid arguments\n");
				} else
					printf("error: invalid arguments\n");
				
			} else if (xmglru_obj != NULL) {
				if (strcmp(buffer, "map") == 0) {
					dump_map(xmglru_fd);
					printf("success: map\n");

				} else if (strcmp(buffer, "age") == 0) {
					err = run_aging(aging_fd, memcg_id);
					if (err)
						printf("error: age %d\n", err);
					else
						printf("success: age\n");

				} else if (strcmp(buffer, "detach") == 0) {
					detach_progs(xmglru_obj);
					xmglru_obj = NULL;
					xmglru_fd = -1;
					aging_fd = -1;
					memcg_id = -1;
					printf("success: detach\n");
				}  else if (strcmp(buffer, "ageseq") == 0) {
					err = run_seq_aging(handle_seq_fd, memcg_id, 10, 1, 50);
					if (err)
						printf("error: age sequential %d\n", err);
					else
						printf("success: age sequential\n");

				}

			}
			else
				printf("error: invalid command\n");	

next:
			free(buffer);
		} else
			printf("error: invalid command\n");
	}
}
