// SPDX-License-Identifier: GPL-2.0-only
/*
 * qos-test.c
 * (c) 2022 len.brown@intel.com
 *
 * Demonstrate the sched_setattr(EQOS) interface,
 * and how it sets EPP of the current task.
 *
 * $ cc -o qos-test qos-test.c
 * $ sudo ./qos-test
 * cpu3: 0x80 Before
 * cpu3: 0xff Max Efficiency
 * cpu3: 0xc0 Balanced Efficiency
 * cpu3: 0x80 Default
 * cpu3: 0x40 Balanced Performance
 * cpu3: 0x00 Max Performance
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>

int max_cpu_num;
size_t cpu_set_size;
char *possible_file = "/sys/devices/system/cpu/possible";

/*
 * Per Task QOS Hints
 */
enum task_eqos_hints {
	EQOS_DEFAULT = 0,
	EQOS_MAX_PERFORMANCE,
	EQOS_BALANCED_PERFORMANCE,
	EQOS_BALANCED_EFFICIENCY,
	EQOS_MAX_EFFICIENCY
};

struct new_sched_attr {
	__u32 size;

	__u32 sched_policy;
	__u64 sched_flags;

	/* SCHED_NORMAL, SCHED_BATCH */
	__s32 sched_nice;

	/* SCHED_FIFO, SCHED_RR */
	__u32 sched_priority;

	/* SCHED_DEADLINE */
	__u64 sched_runtime;
	__u64 sched_deadline;
	__u64 sched_period;

	/* Utilization hints */
	__u32 sched_util_min;
	__u32 sched_util_max;

	/* QOS hints */
	__u64 sched_qos_hints;
};

/*
 * system call wrappers, since glibc doesn't currently provide them
 */
static int sched_setattr(pid_t pid, const struct new_sched_attr *attr, unsigned int flags)
{
	return syscall(SYS_sched_setattr, pid, attr, flags);
}

static int sched_getattr(pid_t pid, struct new_sched_attr *attr, unsigned int size,
			 unsigned int flags)
{
	return syscall(SYS_sched_getattr, pid, attr, size, flags);
}

/*
 * set_my_sched_eqos(eqos)
 * return previous
 */
static unsigned long long set_my_sched_eqos(unsigned long long eqos)
{
	int retval, errno;
	unsigned long long original_eqos;
	struct new_sched_attr *sap;

	errno = 0;

	sap = (struct new_sched_attr *)calloc(1, sizeof(struct new_sched_attr));
	if (sap == NULL)
		err(1, "new_sched_attr");

	retval = sched_getattr(0, sap, sizeof(struct new_sched_attr), 0);
	if (retval)
		err(errno, "sched_getattr");

	sap->size = sizeof(struct new_sched_attr);

	original_eqos = sap->sched_qos_hints;
	sap->sched_qos_hints = eqos;

	retval = sched_setattr(0, sap, 0);
	if (retval)
		err(errno, "sched_setattr");

	free(sap);

	return original_eqos;
}

static int get_msr(int cpu, off_t offset, unsigned long long *msr)
{
	char pathname[32];
	int fd;
	int retval;

	sprintf(pathname, "/dev/cpu/%d/msr", cpu);
	fd = open(pathname, O_RDONLY);
	if (fd < 0)
		err(-1, "%s open failed, try chown or chmod +r /dev/cpu/*/msr, or run as root", pathname);

	retval = pread(fd, msr, sizeof(*msr), offset);
	if (retval != sizeof(*msr))
		warn("cpu%d: msr offset 0x%llx read failed", cpu, (unsigned long long)offset);

	close(fd);

	return 0;
}

char tid_qos_file[128];

#define MSR_HWP_REQUEST                 0x00000774
#define HWP_REQ_TO_EPP(msr)		((unsigned int)(((msr) >> 24) & 0xFF))
static void print_task(pid_t tid, char *s)
{
	int retval;
	unsigned long long msr;
	int cpu = sched_getcpu();
	FILE *fp;
	int my_qos;

	sprintf(tid_qos_file, "/proc/%d/task/%d/qos", tid, tid);

	fp = fopen(tid_qos_file, "r");
	if (fp == NULL)
		err(-1, "open %s", tid_qos_file);

	retval = fscanf(fp, "%d", &my_qos);
	if (retval != 1)
		err(-1, "malformed %s", tid_qos_file);

	retval = get_msr(cpu, MSR_HWP_REQUEST, &msr);

	printf("t%ld cpu%d QOS %d EPP 0x%02x %s\n", (long)tid, cpu, my_qos, HWP_REQ_TO_EPP(msr), s);
}

/*
 * set_my_affinity(cpu_num)
 */
void set_my_affinity(int cpu_num)
{
	cpu_set_t *set;
	int my_cpu;

	set = CPU_ALLOC(max_cpu_num + 1);
	if (set == NULL)
		err(3, "CPU_ALLOC set");

	CPU_ZERO_S(cpu_set_size, set);
	CPU_SET_S(cpu_num, cpu_set_size, set);

	if (sched_setaffinity(0, cpu_set_size, set) == -1)
		err(1, "sched_setaffinity cpu%d", cpu_num);

	my_cpu = sched_getcpu();
	if (my_cpu != cpu_num)
		warn("cpu%d is not cpu%d", my_cpu, cpu_num);

	CPU_FREE(set);
}

void set_all_5_eqos(void)
{
	pid_t tid = gettid();

	set_my_sched_eqos(EQOS_MAX_EFFICIENCY);
	print_task(tid, "Max Efficiency");

	set_my_sched_eqos(EQOS_BALANCED_EFFICIENCY);
	print_task(tid, "Balanced Efficiency");

	set_my_sched_eqos(EQOS_DEFAULT);
	print_task(tid, "Default");

	set_my_sched_eqos(EQOS_BALANCED_PERFORMANCE);
	print_task(tid, "Balanced Performance");

	set_my_sched_eqos(EQOS_MAX_PERFORMANCE);
	print_task(tid, "Max Performance");
}

static int set_max_cpu_num(void)
{
	FILE *filep;
	int retval, num;
	char c;

	filep = fopen(possible_file, "r");
	if (filep == NULL) {
		warn("%s", possible_file);
		return 255;
	}

	while ((retval = fscanf(filep, "%d%c", &num, &c)) == 2) {
		if (c == '\n')
			break;
		if (c != ',' && c != '-')
			errx(1, "Bad Format '%s'", possible_file);
	}
	if (retval != 2)
		errx(1, "Bad format '%s'", possible_file);

	fclose(filep);

	max_cpu_num = num;

	return num;
}

/* use global max_cpu_num and cpu_set_size */
static cpu_set_t *allocate_cpuset(void)
{
	cpu_set_t *set;

	set = CPU_ALLOC(max_cpu_num + 1);
	if (set == NULL)
		err(3, "CPU_ALLOC");

	CPU_ZERO_S(cpu_set_size, set);
	return set;

}

void move_to_another_cpu(void)
{
	cpu_set_t *cpu_set;
	int my_cpu;
	int retval;

	my_cpu = sched_getcpu();

	/*
	 * cpu_set = sched_getaffinity() CPUs we can run on
	 */
	cpu_set = allocate_cpuset();

	retval = sched_getaffinity(0, cpu_set_size, cpu_set);
	if (retval)
		err(retval, "sched_getaffinity");

	/* remove current CPU from set */
	CPU_CLR_S(my_cpu, cpu_set_size, cpu_set);

	/* move off of this CPU */
	if (sched_setaffinity(0, cpu_set_size, cpu_set) == -1)
		err(1, "sched_setaffinity cpu%d", my_cpu);

	CPU_FREE(cpu_set);
}

int fork_it(void)
{
	pid_t child_pid;
	int status;

	/* TODO clear affinity side-effect of previous test */
	//sched_setaffinity(0, cpu_present_setsize, cpu_present_set);

	child_pid = fork();
	if (!child_pid) {

		/* child */
		sleep(1);
		print_task(gettid(), "forked child");

		execl("/usr/bin/sleep", "sleep", "3", (char *)NULL);
		err(errno, "exec sleep");
	} else {

		/* parent */
		if (child_pid == -1)
			err(1, "fork");

		sleep(2);
		print_task(child_pid, "execed child");

		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
		if (waitpid(child_pid, &status, 0) == -1)
			err(status, "waitpid");

		if (WIFEXITED(status))
			status = WEXITSTATUS(status);
	}
}

int main(void)
{
	pid_t tid = gettid();

	print_task(tid, "Before");

	set_all_5_eqos();

	set_max_cpu_num();
	cpu_set_size = CPU_ALLOC_SIZE(max_cpu_num + 1);

	move_to_another_cpu();
	print_task(tid, "after moving");

	fork_it();

	return 0;
}
