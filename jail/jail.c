/*
 * Copyright (C) 2015 John Crispin <blogic@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <sched.h>
#include <linux/limits.h>
#include <signal.h>

#include "capabilities.h"
#include "elf.h"
#include "fs.h"
#include "jail.h"
#include "log.h"

#include <libubox/uloop.h>

#define STACK_SIZE	(1024 * 1024)
#define OPT_ARGS	"S:C:n:h:r:w:d:psulocU:G:E"

static struct {
	char *name;
	char *hostname;
	char **jail_argv;
	char *seccomp;
	char *capabilities;
	char *user;
	char *group;
	int no_new_privs;
	int namespace;
	int procfs;
	int ronly;
	int sysfs;
	int require_jail;
} opts;

static void free_opts(bool all) {
	char **tmp;

	free(opts.hostname);
	if (all) {
		tmp = opts.jail_argv;
		while(*tmp)
			free(*(tmp++));

		free(opts.jail_argv);
	};
}

extern int pivot_root(const char *new_root, const char *put_old);

int debug = 0;

static char child_stack[STACK_SIZE];

static int mkdir_p(char *dir, mode_t mask)
{
	char *l = strrchr(dir, '/');
	int ret;

	if (!l)
		return 0;

	*l = '\0';

	if (mkdir_p(dir, mask))
		return -1;

	*l = '/';

	ret = mkdir(dir, mask);
	if (ret && errno == EEXIST)
		return 0;

	if (ret)
		ERROR("mkdir(%s, %d) failed: %m\n", dir, mask);

	return ret;
}

int mount_bind(const char *root, const char *path, int readonly, int error)
{
	struct stat s;
	char new[PATH_MAX];
	int fd;

	if (stat(path, &s)) {
		ERROR("stat(%s) failed: %m\n", path);
		return error;
	}

	snprintf(new, sizeof(new), "%s%s", root, path);
	if (S_ISDIR(s.st_mode)) {
		mkdir_p(new, 0755);
	} else {
		mkdir_p(dirname(new), 0755);
		snprintf(new, sizeof(new), "%s%s", root, path);
		fd = creat(new, 0644);
		if (fd == -1) {
			ERROR("creat(%s) failed: %m\n", new);
			return -1;
		}
		close(fd);
	}

	if (mount(path, new, NULL, MS_BIND, NULL)) {
		ERROR("failed to mount -B %s %s: %m\n", path, new);
		return -1;
	}

	if (readonly && mount(NULL, new, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL)) {
		ERROR("failed to remount ro %s: %m\n", new);
		return -1;
	}

	DEBUG("mount -B %s %s (%s)\n", path, new, readonly?"ro":"rw");

	return 0;
}

static int build_jail_fs(void)
{
	char jail_root[] = "/tmp/ujail-XXXXXX";
	char tmpdevdir[] = "/tmp/ujail-XXXXXX/dev";

	if (mkdtemp(jail_root) == NULL) {
		ERROR("mkdtemp(%s) failed: %m\n", jail_root);
		return -1;
	}

	/* oldroot can't be MS_SHARED else pivot_root() fails */
	if (mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL)) {
		ERROR("private mount failed %m\n");
		return -1;
	}

	if (mount("tmpfs", jail_root, "tmpfs", MS_NOATIME, "mode=0755")) {
		ERROR("tmpfs mount failed %m\n");
		return -1;
	}

	if (chdir(jail_root)) {
		ERROR("chdir(%s) (jail_root) failed: %m\n", jail_root);
		return -1;
	}

	snprintf(tmpdevdir, sizeof(tmpdevdir), "%s/dev", jail_root);
	mkdir_p(tmpdevdir, 0755);
	if (mount(NULL, tmpdevdir, "tmpfs", MS_NOATIME | MS_NOEXEC | MS_NOSUID, "size=1M"))
		return -1;

	if (mount_all(jail_root)) {
		ERROR("mount_all() failed\n");
		return -1;
	}

	char dirbuf[sizeof(jail_root) + 4];
	snprintf(dirbuf, sizeof(dirbuf), "%s/old", jail_root);
	mkdir(dirbuf, 0755);

	if (pivot_root(jail_root, dirbuf) == -1) {
		ERROR("pivot_root(%s, %s) failed: %m\n", jail_root, dirbuf);
<<<<<<< HEAD
		return -1;
	}
	if (chdir("/")) {
		ERROR("chdir(/) (after pivot_root) failed: %m\n");
		return -1;
=======
		free_and_exit(-1);
	}
	if (chdir("/")) {
		ERROR("chdir(/) (after pivot_root) failed: %m\n");
		free_and_exit(-1);
>>>>>>> 3019f50 (jail: leak less memory)
	}

	snprintf(dirbuf, sizeof(dirbuf), "/old%s", jail_root);
	rmdir(dirbuf);
	umount2("/old", MNT_DETACH);
	rmdir("/old");

<<<<<<< HEAD
	if (opts.procfs) {
		mkdir("/proc", 0755);
		mount("proc", "/proc", "proc", MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID, 0);
		/*
		 * make /proc/sys read-only
		 */

		mount("/proc/sys", "/proc/sys", NULL, MS_BIND, 0);
		mount(NULL, "/proc/sys", NULL, MS_REMOUNT | MS_RDONLY, 0);
		mount(NULL, "/proc", NULL, MS_REMOUNT, 0);
	}
	if (opts.sysfs) {
		mkdir("/sys", 0755);
		mount("sysfs", "/sys", "sysfs", MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RDONLY, 0);
=======
	if (create_devices()) {
		ERROR("create_devices() failed\n");
		free_and_exit(-1);
>>>>>>> 3019f50 (jail: leak less memory)
	}
	if (opts.ronly)
		mount(NULL, "/", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, 0);

<<<<<<< HEAD
=======
	umask(old_umask);
	post_jail_fs();
}

static int write_uid_gid_map(pid_t child_pid, bool gidmap, char *mapstr)
{
	int map_file;
	char map_path[64];

	if (snprintf(map_path, sizeof(map_path), "/proc/%d/%s",
		child_pid, gidmap?"gid_map":"uid_map") < 0)
		return -1;

	if ((map_file = open(map_path, O_WRONLY)) == -1)
		return -1;

	if (dprintf(map_file, "%s", mapstr)) {
		close(map_file);
		return -1;
	}

	close(map_file);
	return 0;
}

static int write_single_uid_gid_map(pid_t child_pid, bool gidmap, int id)
{
	int map_file;
	char map_path[64];
	const char *map_format = "%d %d %d\n";
	if (snprintf(map_path, sizeof(map_path), "/proc/%d/%s",
		child_pid, gidmap?"gid_map":"uid_map") < 0)
		return -1;

	if ((map_file = open(map_path, O_WRONLY)) == -1)
		return -1;

	if (dprintf(map_file, map_format, 0, id, 1) == -1) {
		close(map_file);
		return -1;
	}

	close(map_file);
	return 0;
}

static int write_setgroups(pid_t child_pid, bool allow)
{
	int setgroups_file;
	char setgroups_path[64];

	if (snprintf(setgroups_path, sizeof(setgroups_path), "/proc/%d/setgroups",
		child_pid) < 0) {
		return -1;
	}

	if ((setgroups_file = open(setgroups_path, O_WRONLY)) == -1) {
		return -1;
	}

	if (dprintf(setgroups_file, "%s", allow?"allow":"deny") == -1) {
		close(setgroups_file);
		return -1;
	}

	close(setgroups_file);
	return 0;
}

static void get_jail_user(int *user, int *user_gid, int *gr_gid)
{
	struct passwd *p = NULL;
	struct group *g = NULL;

	if (opts.user) {
		p = getpwnam(opts.user);
		if (!p) {
			ERROR("failed to get uid/gid for user %s: %d (%s)\n",
			      opts.user, errno, strerror(errno));
			free_and_exit(EXIT_FAILURE);
		}
		*user = p->pw_uid;
		*user_gid = p->pw_gid;
	} else {
		*user = -1;
		*user_gid = -1;
	}

	if (opts.group) {
		g = getgrnam(opts.group);
		if (!g) {
			ERROR("failed to get gid for group %s: %m\n", opts.group);
			free_and_exit(EXIT_FAILURE);
		}
		*gr_gid = g->gr_gid;
	} else {
		*gr_gid = -1;
	}
};

static void set_jail_user(int pw_uid, int user_gid, int gr_gid)
{
	if (opts.user && (user_gid != -1) && initgroups(opts.user, user_gid)) {
		ERROR("failed to initgroups() for user %s: %m\n", opts.user);
		free_and_exit(EXIT_FAILURE);
	}

	if ((gr_gid != -1) && setregid(gr_gid, gr_gid)) {
		ERROR("failed to set group id %d: %m\n", gr_gid);
		free_and_exit(EXIT_FAILURE);
	}

	if ((pw_uid != -1) && setreuid(pw_uid, pw_uid)) {
		ERROR("failed to set user id %d: %m\n", pw_uid);
		free_and_exit(EXIT_FAILURE);
	}
}

static int apply_rlimits(void)
{
	int resource;

	for (resource = 0; resource < RLIM_NLIMITS; ++resource) {
		if (opts.rlimits[resource])
			DEBUG("applying limits to resource %u\n", resource);

		if (opts.rlimits[resource] &&
		    setrlimit(resource, opts.rlimits[resource]))
			return errno;
	}

>>>>>>> 3019f50 (jail: leak less memory)
	return 0;
}

#define MAX_ENVP	8
static char** build_envp(const char *seccomp)
{
	static char *envp[MAX_ENVP];
	static char preload_var[PATH_MAX];
	static char seccomp_var[PATH_MAX];
	static char debug_var[] = "LD_DEBUG=all";
	const char *preload_lib = find_lib("libpreload-seccomp.so");
	int count = 0;

	if (seccomp && !preload_lib) {
		ERROR("failed to add preload-lib to env\n");
		return NULL;
	}
	if (seccomp) {
		snprintf(seccomp_var, sizeof(seccomp_var), "SECCOMP_FILE=%s", seccomp);
		envp[count++] = seccomp_var;
		snprintf(preload_var, sizeof(preload_var), "LD_PRELOAD=%s", preload_lib);
		envp[count++] = preload_var;
	}
	if (debug > 1)
		envp[count++] = debug_var;
	
	envp[count] = NULL;

	return envp;
}

static void usage(void)
{
	fprintf(stderr, "ujail <options> -- <binary> <params ...>\n");
	fprintf(stderr, "  -d <num>\tshow debug log (increase num to increase verbosity)\n");
	fprintf(stderr, "  -S <file>\tseccomp filter config\n");
	fprintf(stderr, "  -C <file>\tcapabilities drop config\n");
	fprintf(stderr, "  -c\t\tset PR_SET_NO_NEW_PRIVS\n");
	fprintf(stderr, "  -n <name>\tthe name of the jail\n");
	fprintf(stderr, "namespace jail options:\n");
	fprintf(stderr, "  -h <hostname>\tchange the hostname of the jail\n");
	fprintf(stderr, "  -r <file>\treadonly files that should be staged\n");
	fprintf(stderr, "  -w <file>\twriteable files that should be staged\n");
	fprintf(stderr, "  -p\t\tjail has /proc\n");
	fprintf(stderr, "  -s\t\tjail has /sys\n");
	fprintf(stderr, "  -l\t\tjail has /dev/log\n");
	fprintf(stderr, "  -u\t\tjail has a ubus socket\n");
	fprintf(stderr, "  -U <name>\tuser to run jailed process\n");
	fprintf(stderr, "  -G <name>\tgroup to run jailed process\n");
	fprintf(stderr, "  -o\t\tremont jail root (/) read only\n");
	fprintf(stderr, "  -E\t\tfail if jail cannot be setup\n");
	fprintf(stderr, "\nWarning: by default root inside the jail is the same\n\
and he has the same powers as root outside the jail,\n\
thus he can escape the jail and/or break stuff.\n\
Please use seccomp/capabilities (-S/-C) to restrict his powers\n\n\
If you use none of the namespace jail options,\n\
ujail will not use namespace/build a jail,\n\
and will only drop capabilities/apply seccomp filter.\n\n");
}

static int exec_jail(void *_notused)
{
	struct passwd *p = NULL;
	struct group *g = NULL;

	if (opts.capabilities && drop_capabilities(opts.capabilities))
		exit(EXIT_FAILURE);

	if (opts.no_new_privs && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
                ERROR("prctl(PR_SET_NO_NEW_PRIVS) failed: %m\n");
		exit(EXIT_FAILURE);
	}

	if (opts.namespace && opts.hostname && strlen(opts.hostname) > 0
			&& sethostname(opts.hostname, strlen(opts.hostname))) {
		ERROR("sethostname(%s) failed: %m\n", opts.hostname);
		exit(EXIT_FAILURE);
	}

	if (opts.namespace && build_jail_fs()) {
		ERROR("failed to build jail fs\n");
		exit(EXIT_FAILURE);
	}

	if (opts.user) {
		p = getpwnam(opts.user);
		if (!p) {
			ERROR("failed to get uid/gid for user %s: %d (%s)\n",
			      opts.user, errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (opts.group) {
		g = getgrnam(opts.group);
		if (!g) {
			ERROR("failed to get gid for group %s: %m\n", opts.group);
			exit(EXIT_FAILURE);
		}
	}

	if (p && p->pw_gid && initgroups(opts.user, p->pw_gid)) {
		ERROR("failed to initgroups() for user %s: %m\n", opts.user);
		exit(EXIT_FAILURE);
	}

	if (g && g->gr_gid && setgid(g->gr_gid)) {
		ERROR("failed to set group id %d: %m\n", g?g->gr_gid:p->pw_gid);
		exit(EXIT_FAILURE);
	}

	if (p && p->pw_uid && setuid(p->pw_uid)) {
		ERROR("failed to set user id %d: %m\n", p->pw_uid);
		exit(EXIT_FAILURE);
	}


	char **envp = build_envp(opts.seccomp);
	if (!envp)
		exit(EXIT_FAILURE);

	free_opts(false);
	INFO("exec-ing %s\n", *opts.jail_argv);
	execve(*opts.jail_argv, opts.jail_argv, envp);
	/* we get there only if execve fails */
	ERROR("failed to execve %s: %m\n", *opts.jail_argv);
	exit(EXIT_FAILURE);
}

static int jail_running = 1;
static int jail_return_code = 0;

static void jail_process_timeout_cb(struct uloop_timeout *t);
static struct uloop_timeout jail_process_timeout = {
	.cb = jail_process_timeout_cb,
};

static void jail_process_handler(struct uloop_process *c, int ret)
{
	uloop_timeout_cancel(&jail_process_timeout);
	if (WIFEXITED(ret)) {
		jail_return_code = WEXITSTATUS(ret);
		INFO("jail (%d) exited with exit: %d\n", c->pid, jail_return_code);
	} else {
		jail_return_code = WTERMSIG(ret);
		INFO("jail (%d) exited with signal: %d\n", c->pid, jail_return_code);
	}
	jail_running = 0;
	uloop_end();
}

static struct uloop_process jail_process = {
	.cb = jail_process_handler,
};

static void jail_process_timeout_cb(struct uloop_timeout *t)
{
	DEBUG("jail process failed to stop, sending SIGKILL\n");
	kill(jail_process.pid, SIGKILL);
}

static void jail_handle_signal(int signo)
{
	DEBUG("forwarding signal %d to the jailed process\n", signo);
	kill(jail_process.pid, signo);
}

<<<<<<< HEAD
=======
static void signals_init(void)
{
	int i;
	sigset_t sigmask;

	sigfillset(&sigmask);
	for (i = 0; i < _NSIG; i++) {
		struct sigaction s = { 0 };

		if (!sigismember(&sigmask, i))
			continue;
		if ((i == SIGCHLD) || (i == SIGPIPE) || (i == SIGSEGV))
			continue;

		s.sa_handler = jail_handle_signal;
		sigaction(i, &s, NULL);
	}
}

static void pre_exec_jail(struct uloop_timeout *t);
static struct uloop_timeout pre_exec_timeout = {
	.cb = pre_exec_jail,
};

int pipes[4];
static int exec_jail(void *arg)
{
	char buf[1];

	exit_from_child = true;
	uloop_init();
	signals_init();

	close(pipes[0]);
	close(pipes[3]);

	setns_open(CLONE_NEWUSER);
	setns_open(CLONE_NEWNET);
	setns_open(CLONE_NEWNS);
	setns_open(CLONE_NEWIPC);
	setns_open(CLONE_NEWUTS);

	buf[0] = 'i';
	if (write(pipes[1], buf, 1) < 1) {
		ERROR("can't write to parent\n");
		return EXIT_FAILURE;
	}
	close(pipes[1]);
	if (read(pipes[2], buf, 1) < 1) {
		ERROR("can't read from parent\n");
		return EXIT_FAILURE;
	}
	if (buf[0] != 'O') {
		ERROR("parent had an error, child exiting\n");
		return EXIT_FAILURE;
	}

	if (opts.namespace & CLONE_NEWCGROUP)
		unshare(CLONE_NEWCGROUP);

	if ((opts.namespace & CLONE_NEWUSER) || (opts.setns.user != -1)) {
		if (setregid(0, 0) < 0) {
			ERROR("setgid\n");
			free_and_exit(EXIT_FAILURE);
		}
		if (setreuid(0, 0) < 0) {
			ERROR("setuid\n");
			free_and_exit(EXIT_FAILURE);
		}
		if (setgroups(0, NULL) < 0) {
			ERROR("setgroups\n");
			free_and_exit(EXIT_FAILURE);
		}
	}

	if (opts.namespace && opts.hostname && strlen(opts.hostname) > 0
			&& sethostname(opts.hostname, strlen(opts.hostname))) {
		ERROR("sethostname(%s) failed: %m\n", opts.hostname);
		free_and_exit(EXIT_FAILURE);
	}

	uloop_timeout_add(&pre_exec_timeout);
	uloop_run();

	free_and_exit(-1);
	return -1;
}

static void pre_exec_jail(struct uloop_timeout *t)
{
	if ((opts.namespace & CLONE_NEWNS) && build_jail_fs()) {
		ERROR("failed to build jail fs\n");
		free_and_exit(EXIT_FAILURE);
	} else {
		run_hooks(opts.hooks.createContainer, post_jail_fs);
	}
}

static void post_start_hook(void);
static void post_jail_fs(void)
{
	char buf[1];

	if (read(pipes[2], buf, 1) < 1) {
		ERROR("can't read from parent\n");
		free_and_exit(EXIT_FAILURE);
	}
	if (buf[0] != '!') {
		ERROR("parent had an error, child exiting\n");
		free_and_exit(EXIT_FAILURE);
	}
	close(pipes[2]);

	run_hooks(opts.hooks.startContainer, post_start_hook);
}

static void post_start_hook(void)
{
	int pw_uid, pw_gid, gr_gid;

	/*
	 * make sure setuid/setgid won't drop capabilities in case capabilities
	 * have been specified explicitely.
	 */
	if (opts.capset.apply) {
		if (prctl(PR_SET_SECUREBITS, SECBIT_NO_SETUID_FIXUP)) {
			ERROR("prctl(PR_SET_SECUREBITS) failed: %m\n");
			free_and_exit(EXIT_FAILURE);
		}
	}

	/* drop capabilities, retain those still needed to further setup jail */
	if (applyOCIcapabilities(opts.capset, (1LLU << CAP_SETGID) | (1LLU << CAP_SETUID) | (1LLU << CAP_SETPCAP)))
		free_and_exit(EXIT_FAILURE);

	/* use either cmdline-supplied user/group or uid/gid from OCI spec */
	get_jail_user(&pw_uid, &pw_gid, &gr_gid);
	set_jail_user(opts.pw_uid?:pw_uid, opts.pw_gid?:pw_gid, opts.gr_gid?:gr_gid);

	if (opts.additional_gids &&
	    (setgroups(opts.num_additional_gids, opts.additional_gids) < 0)) {
		ERROR("setgroups failed: %m\n");
		free_and_exit(EXIT_FAILURE);
	}

	if (opts.set_umask)
		umask(opts.umask);

	/* restore securebits back to normal */
	if (opts.capset.apply) {
		if (prctl(PR_SET_SECUREBITS, 0)) {
			ERROR("prctl(PR_SET_SECUREBITS) failed: %m\n");
			free_and_exit(EXIT_FAILURE);
		}
	}

	/* drop remaining capabilities to end up with specified sets */
	if (applyOCIcapabilities(opts.capset, 0))
		free_and_exit(EXIT_FAILURE);

	if (opts.no_new_privs && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		ERROR("prctl(PR_SET_NO_NEW_PRIVS) failed: %m\n");
		free_and_exit(EXIT_FAILURE);
	}

	char **envp = build_envp(opts.seccomp, opts.envp);
	if (!envp)
		free_and_exit(EXIT_FAILURE);

	if (opts.cwd && chdir(opts.cwd))
		free_and_exit(EXIT_FAILURE);

	if (opts.ociseccomp && applyOCIlinuxseccomp(opts.ociseccomp))
		free_and_exit(EXIT_FAILURE);

	uloop_end();
	free_opts(false);
	INFO("exec-ing %s\n", *opts.jail_argv);
	if (opts.envp) /* respect PATH if potentially set in ENV */
		execvpe(*opts.jail_argv, opts.jail_argv, envp);
	else
		execve(*opts.jail_argv, opts.jail_argv, envp);

	/* we get there only if execve fails */
	ERROR("failed to execve %s: %m\n", *opts.jail_argv);
	exit(EXIT_FAILURE);
}

static int ns_open_pid(const char *nstype, const pid_t target_ns)
{
	char pid_pid_path[PATH_MAX];

	snprintf(pid_pid_path, sizeof(pid_pid_path), "/proc/%u/ns/%s", target_ns, nstype);

	return open(pid_pid_path, O_RDONLY);
}

static void netns_updown(pid_t pid, bool start)
{
	static struct blob_buf req;
	uint32_t id;

	if (!parent_ctx)
		return;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "jail", opts.name);
	blobmsg_add_u32(&req, "pid", pid);
	blobmsg_add_u8(&req, "start", start);

	if (ubus_lookup_id(parent_ctx, "network", &id) ||
	    ubus_invoke(parent_ctx, id, "netns_updown", req.head, NULL, NULL, 3000))
		INFO("ubus request failed\n");

	blob_buf_free(&req);
}

static int parseOCIenvarray(struct blob_attr *msg, char ***envp)
{
	struct blob_attr *cur;
	int sz = 0, rem;

	blobmsg_for_each_attr(cur, msg, rem)
		++sz;

	if (sz > 0) {
		*envp = calloc(1 + sz, sizeof(char*));
		if (!(*envp))
			return ENOMEM;
	} else {
		*envp = NULL;
		return 0;
	}

	sz = 0;
	blobmsg_for_each_attr(cur, msg, rem)
		(*envp)[sz++] = strdup(blobmsg_get_string(cur));

	if (sz)
		(*envp)[sz] = NULL;

	return 0;
}

enum {
	OCI_ROOT_PATH,
	OCI_ROOT_READONLY,
	__OCI_ROOT_MAX,
};

static const struct blobmsg_policy oci_root_policy[] = {
	[OCI_ROOT_PATH] = { "path", BLOBMSG_TYPE_STRING },
	[OCI_ROOT_READONLY] = { "readonly", BLOBMSG_TYPE_BOOL },
};

static int parseOCIroot(const char *jsonfile, struct blob_attr *msg)
{
	static char extroot[PATH_MAX] = { 0 };
	struct blob_attr *tb[__OCI_ROOT_MAX];
	char *cur;
	char *root_path;

	blobmsg_parse(oci_root_policy, __OCI_ROOT_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_ROOT_PATH])
		return ENODATA;

	root_path = blobmsg_get_string(tb[OCI_ROOT_PATH]);

	/* prepend bundle directory in case of relative paths */
	if (root_path[0] != '/') {
		strncpy(extroot, jsonfile, PATH_MAX);
		cur = strrchr(extroot, '/');

		if (!cur)
			return ENOTDIR;

		*(++cur) = '\0';
	}

	strncat(extroot, root_path, PATH_MAX - (strlen(extroot) + 1));

	opts.extroot = extroot;

	if (tb[OCI_ROOT_READONLY])
		opts.ronly = blobmsg_get_bool(tb[OCI_ROOT_READONLY]);

	return 0;
}


enum {
	OCI_HOOK_PATH,
	OCI_HOOK_ARGS,
	OCI_HOOK_ENV,
	OCI_HOOK_TIMEOUT,
	__OCI_HOOK_MAX,
};

static const struct blobmsg_policy oci_hook_policy[] = {
	[OCI_HOOK_PATH] = { "path", BLOBMSG_TYPE_STRING },
	[OCI_HOOK_ARGS] = { "args", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOK_ENV] = { "env", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOK_TIMEOUT] = { "timeout", BLOBMSG_TYPE_INT32 },
};


static int parseOCIhook(struct hook_execvpe ***hooklist, struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_HOOK_MAX];
	struct blob_attr *cur;
	int rem, ret = 0;
	int idx = 0;

	blobmsg_for_each_attr(cur, msg, rem)
		++idx;

	if (!idx)
		return 0;

	*hooklist = calloc(idx + 1, sizeof(struct hook_execvpe *));
	idx = 0;

	if (!(*hooklist))
		return ENOMEM;

	blobmsg_for_each_attr(cur, msg, rem) {
		blobmsg_parse(oci_hook_policy, __OCI_HOOK_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (!tb[OCI_HOOK_PATH]) {
			ret = EINVAL;
			goto errout;
		}

		(*hooklist)[idx] = calloc(1, sizeof(struct hook_execvpe));
		if (tb[OCI_HOOK_ARGS]) {
			ret = parseOCIenvarray(tb[OCI_HOOK_ARGS], &((*hooklist)[idx]->argv));
			if (ret)
				goto errout;
		} else {
			(*hooklist)[idx]->argv = calloc(2, sizeof(char *));
			((*hooklist)[idx]->argv)[0] = strdup(blobmsg_get_string(tb[OCI_HOOK_PATH]));
			((*hooklist)[idx]->argv)[1] = NULL;
		};


		if (tb[OCI_HOOK_ENV]) {
			ret = parseOCIenvarray(tb[OCI_HOOK_ENV], &((*hooklist)[idx]->envp));
			if (ret)
				goto errout;
		}

		if (tb[OCI_HOOK_TIMEOUT])
			(*hooklist)[idx]->timeout = blobmsg_get_u32(tb[OCI_HOOK_TIMEOUT]);

		(*hooklist)[idx]->file = strdup(blobmsg_get_string(tb[OCI_HOOK_PATH]));

		++idx;
	}

	(*hooklist)[idx] = NULL;

	DEBUG("added %d hooks\n", idx);

	return 0;

errout:
	free_hooklist(*hooklist);
	*hooklist = NULL;

	return ret;
};


enum {
	OCI_HOOKS_PRESTART,
	OCI_HOOKS_CREATERUNTIME,
	OCI_HOOKS_CREATECONTAINER,
	OCI_HOOKS_STARTCONTAINER,
	OCI_HOOKS_POSTSTART,
	OCI_HOOKS_POSTSTOP,
	__OCI_HOOKS_MAX,
};

static const struct blobmsg_policy oci_hooks_policy[] = {
	[OCI_HOOKS_PRESTART] = { "prestart", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOKS_CREATERUNTIME] = { "createRuntime", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOKS_CREATECONTAINER] = { "createContainer", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOKS_STARTCONTAINER] = { "startContainer", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOKS_POSTSTART] = { "poststart", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOKS_POSTSTOP] = { "poststop", BLOBMSG_TYPE_ARRAY },
};

static int parseOCIhooks(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_HOOKS_MAX];
	int ret;

	blobmsg_parse(oci_hooks_policy, __OCI_HOOKS_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_HOOKS_PRESTART])
		INFO("warning: ignoring deprecated prestart hook\n");

	if (tb[OCI_HOOKS_CREATERUNTIME]) {
		ret = parseOCIhook(&opts.hooks.createRuntime, tb[OCI_HOOKS_CREATERUNTIME]);
		if (ret)
			return ret;
	}

	if (tb[OCI_HOOKS_CREATECONTAINER]) {
		ret = parseOCIhook(&opts.hooks.createContainer, tb[OCI_HOOKS_CREATECONTAINER]);
		if (ret)
			goto out_createruntime;
	}

	if (tb[OCI_HOOKS_STARTCONTAINER]) {
		ret = parseOCIhook(&opts.hooks.startContainer, tb[OCI_HOOKS_STARTCONTAINER]);
		if (ret)
			goto out_createcontainer;
	}

	if (tb[OCI_HOOKS_POSTSTART]) {
		ret = parseOCIhook(&opts.hooks.poststart, tb[OCI_HOOKS_POSTSTART]);
		if (ret)
			goto out_startcontainer;
	}

	if (tb[OCI_HOOKS_POSTSTOP]) {
		ret = parseOCIhook(&opts.hooks.poststop, tb[OCI_HOOKS_POSTSTOP]);
		if (ret)
			goto out_poststart;
	}

	return 0;

out_poststart:
	free_hooklist(opts.hooks.poststart);
out_startcontainer:
	free_hooklist(opts.hooks.startContainer);
out_createcontainer:
	free_hooklist(opts.hooks.createContainer);
out_createruntime:
	free_hooklist(opts.hooks.createRuntime);

	return ret;
};


enum {
	OCI_PROCESS_USER_UID,
	OCI_PROCESS_USER_GID,
	OCI_PROCESS_USER_UMASK,
	OCI_PROCESS_USER_ADDITIONALGIDS,
	__OCI_PROCESS_USER_MAX,
};

static const struct blobmsg_policy oci_process_user_policy[] = {
	[OCI_PROCESS_USER_UID] = { "uid", BLOBMSG_TYPE_INT32 },
	[OCI_PROCESS_USER_GID] = { "gid", BLOBMSG_TYPE_INT32 },
	[OCI_PROCESS_USER_UMASK] = { "umask", BLOBMSG_TYPE_INT32 },
	[OCI_PROCESS_USER_ADDITIONALGIDS] = { "additionalGids", BLOBMSG_TYPE_ARRAY },
};

static int parseOCIprocessuser(struct blob_attr *msg) {
	struct blob_attr *tb[__OCI_PROCESS_USER_MAX];
	struct blob_attr *cur;
	int rem;
	int has_gid = 0;

	blobmsg_parse(oci_process_user_policy, __OCI_PROCESS_USER_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_PROCESS_USER_UID])
		opts.pw_uid = blobmsg_get_u32(tb[OCI_PROCESS_USER_UID]);

	if (tb[OCI_PROCESS_USER_GID]) {
		opts.pw_gid = blobmsg_get_u32(tb[OCI_PROCESS_USER_GID]);
		opts.gr_gid = blobmsg_get_u32(tb[OCI_PROCESS_USER_GID]);
		has_gid = 1;
	}

	if (tb[OCI_PROCESS_USER_ADDITIONALGIDS]) {
		size_t gidcnt = 0;

		blobmsg_for_each_attr(cur, tb[OCI_PROCESS_USER_ADDITIONALGIDS], rem) {
			++gidcnt;
			if (has_gid && (blobmsg_get_u32(cur) == opts.gr_gid))
				continue;
		}

		if (gidcnt) {
			opts.additional_gids = calloc(gidcnt + has_gid, sizeof(gid_t));
			gidcnt = 0;

			/* always add primary GID to set of GIDs if set */
			if (has_gid)
				opts.additional_gids[gidcnt++] = opts.gr_gid;

			blobmsg_for_each_attr(cur, tb[OCI_PROCESS_USER_ADDITIONALGIDS], rem) {
				if (has_gid && (blobmsg_get_u32(cur) == opts.gr_gid))
					continue;
				opts.additional_gids[gidcnt++] = blobmsg_get_u32(cur);
			}
			opts.num_additional_gids = gidcnt;
		}
		DEBUG("read %zu additional groups\n", gidcnt);
	}

	if (tb[OCI_PROCESS_USER_UMASK]) {
		opts.umask = blobmsg_get_u32(tb[OCI_PROCESS_USER_UMASK]);
		opts.set_umask = true;
	}

	return 0;
}

enum {
	OCI_PROCESS_RLIMIT_TYPE,
	OCI_PROCESS_RLIMIT_SOFT,
	OCI_PROCESS_RLIMIT_HARD,
	__OCI_PROCESS_RLIMIT_MAX,
};

static const struct blobmsg_policy oci_process_rlimit_policy[] = {
	[OCI_PROCESS_RLIMIT_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[OCI_PROCESS_RLIMIT_SOFT] = { "soft", BLOBMSG_CAST_INT64 },
	[OCI_PROCESS_RLIMIT_HARD] = { "hard", BLOBMSG_CAST_INT64 },
};

/* from manpage GETRLIMIT(2) */
static const char* const rlimit_names[RLIM_NLIMITS] = {
	[RLIMIT_AS] = "AS",
	[RLIMIT_CORE] = "CORE",
	[RLIMIT_CPU] = "CPU",
	[RLIMIT_DATA] = "DATA",
	[RLIMIT_FSIZE] = "FSIZE",
	[RLIMIT_LOCKS] = "LOCKS",
	[RLIMIT_MEMLOCK] = "MEMLOCK",
	[RLIMIT_MSGQUEUE] = "MSGQUEUE",
	[RLIMIT_NICE] = "NICE",
	[RLIMIT_NOFILE] = "NOFILE",
	[RLIMIT_NPROC] = "NPROC",
	[RLIMIT_RSS] = "RSS",
	[RLIMIT_RTPRIO] = "RTPRIO",
	[RLIMIT_RTTIME] = "RTTIME",
	[RLIMIT_SIGPENDING] = "SIGPENDING",
	[RLIMIT_STACK] = "STACK",
};

static int resolve_rlimit(char *type) {
	unsigned int rltype;

	for (rltype = 0; rltype < RLIM_NLIMITS; ++rltype)
		if (rlimit_names[rltype] &&
		    !strncmp("RLIMIT_", type, 7) &&
		    !strcmp(rlimit_names[rltype], type + 7))
			return rltype;

	return -1;
}


static int parseOCIrlimit(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_PROCESS_RLIMIT_MAX];
	int limtype = -1;
	struct rlimit *curlim;

	blobmsg_parse(oci_process_rlimit_policy, __OCI_PROCESS_RLIMIT_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_PROCESS_RLIMIT_TYPE] ||
	    !tb[OCI_PROCESS_RLIMIT_SOFT] ||
	    !tb[OCI_PROCESS_RLIMIT_HARD])
		return ENODATA;

	limtype = resolve_rlimit(blobmsg_get_string(tb[OCI_PROCESS_RLIMIT_TYPE]));

	if (limtype < 0)
		return EINVAL;

	if (opts.rlimits[limtype])
		return ENOTUNIQ;

	curlim = malloc(sizeof(struct rlimit));
	curlim->rlim_cur = blobmsg_cast_u64(tb[OCI_PROCESS_RLIMIT_SOFT]);
	curlim->rlim_max = blobmsg_cast_u64(tb[OCI_PROCESS_RLIMIT_HARD]);

	opts.rlimits[limtype] = curlim;

	return 0;
};

enum {
	OCI_PROCESS_ARGS,
	OCI_PROCESS_CAPABILITIES,
	OCI_PROCESS_CWD,
	OCI_PROCESS_ENV,
	OCI_PROCESS_OOMSCOREADJ,
	OCI_PROCESS_NONEWPRIVILEGES,
	OCI_PROCESS_RLIMITS,
	OCI_PROCESS_TERMINAL,
	OCI_PROCESS_USER,
	__OCI_PROCESS_MAX,
};

static const struct blobmsg_policy oci_process_policy[] = {
	[OCI_PROCESS_ARGS] = { "args", BLOBMSG_TYPE_ARRAY },
	[OCI_PROCESS_CAPABILITIES] = { "capabilities", BLOBMSG_TYPE_TABLE },
	[OCI_PROCESS_CWD] = { "cwd", BLOBMSG_TYPE_STRING },
	[OCI_PROCESS_ENV] = { "env", BLOBMSG_TYPE_ARRAY },
	[OCI_PROCESS_OOMSCOREADJ] = { "oomScoreAdj", BLOBMSG_TYPE_INT32 },
	[OCI_PROCESS_NONEWPRIVILEGES] = { "noNewPrivileges", BLOBMSG_TYPE_BOOL },
	[OCI_PROCESS_RLIMITS] = { "rlimits", BLOBMSG_TYPE_ARRAY },
	[OCI_PROCESS_TERMINAL] = { "terminal", BLOBMSG_TYPE_BOOL },
	[OCI_PROCESS_USER] = { "user", BLOBMSG_TYPE_TABLE },
};


static int parseOCIprocess(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_PROCESS_MAX], *cur;
	int rem, res;

	blobmsg_parse(oci_process_policy, __OCI_PROCESS_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_PROCESS_ARGS])
		return ENOENT;

	res = parseOCIenvarray(tb[OCI_PROCESS_ARGS], &opts.jail_argv);
	if (res)
		return res;

	if (tb[OCI_PROCESS_TERMINAL])
		opts.console = blobmsg_get_bool(tb[OCI_PROCESS_TERMINAL]);

	if (tb[OCI_PROCESS_NONEWPRIVILEGES])
		opts.no_new_privs = blobmsg_get_bool(tb[OCI_PROCESS_NONEWPRIVILEGES]);

	if (tb[OCI_PROCESS_CWD])
		opts.cwd = strdup(blobmsg_get_string(tb[OCI_PROCESS_CWD]));

	if (tb[OCI_PROCESS_ENV]) {
		res = parseOCIenvarray(tb[OCI_PROCESS_ENV], &opts.envp);
		if (res)
			return res;
	}

	if (tb[OCI_PROCESS_USER] && (res = parseOCIprocessuser(tb[OCI_PROCESS_USER])))
		return res;

	if (tb[OCI_PROCESS_CAPABILITIES] &&
	    (res = parseOCIcapabilities(&opts.capset, tb[OCI_PROCESS_CAPABILITIES])))
		return res;

	if (tb[OCI_PROCESS_RLIMITS]) {
		blobmsg_for_each_attr(cur, tb[OCI_PROCESS_RLIMITS], rem) {
			res = parseOCIrlimit(cur);
			if (res)
				return res;
		}
	}

	if (tb[OCI_PROCESS_OOMSCOREADJ]) {
		opts.oom_score_adj = blobmsg_get_u32(tb[OCI_PROCESS_OOMSCOREADJ]);
		opts.set_oom_score_adj = true;
	}

	return 0;
}

enum {
	OCI_LINUX_NAMESPACE_TYPE,
	OCI_LINUX_NAMESPACE_PATH,
	__OCI_LINUX_NAMESPACE_MAX,
};

static const struct blobmsg_policy oci_linux_namespace_policy[] = {
	[OCI_LINUX_NAMESPACE_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[OCI_LINUX_NAMESPACE_PATH] = { "path", BLOBMSG_TYPE_STRING },
};

static int resolve_nstype(char *type) {
	if (!strcmp("pid", type))
		return CLONE_NEWPID;
	else if (!strcmp("network", type))
		return CLONE_NEWNET;
	else if (!strcmp("mount", type))
		return CLONE_NEWNS;
	else if (!strcmp("ipc", type))
		return CLONE_NEWIPC;
	else if (!strcmp("uts", type))
		return CLONE_NEWUTS;
	else if (!strcmp("user", type))
		return CLONE_NEWUSER;
	else if (!strcmp("cgroup", type))
		return CLONE_NEWCGROUP;
#ifdef CLONE_NEWTIME
	else if (!strcmp("time", type))
		return CLONE_NEWTIME;
#endif
	else
		return 0;
}

static int parseOCIlinuxns(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_NAMESPACE_MAX];
	int nstype;
	int *setns;
	int fd;

	blobmsg_parse(oci_linux_namespace_policy, __OCI_LINUX_NAMESPACE_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_LINUX_NAMESPACE_TYPE])
		return EINVAL;

	nstype = resolve_nstype(blobmsg_get_string(tb[OCI_LINUX_NAMESPACE_TYPE]));
	if (!nstype)
		return EINVAL;

	if (opts.namespace & nstype)
		return ENOTUNIQ;

	setns = get_namespace_fd(nstype);

	if (!setns)
		return EFAULT;

	if (*setns != -1)
		return ENOTUNIQ;

	if (tb[OCI_LINUX_NAMESPACE_PATH]) {
		DEBUG("opening existing %s namespace from path %s\n",
			blobmsg_get_string(tb[OCI_LINUX_NAMESPACE_TYPE]),
			blobmsg_get_string(tb[OCI_LINUX_NAMESPACE_PATH]));

		fd = open(blobmsg_get_string(tb[OCI_LINUX_NAMESPACE_PATH]), O_RDONLY);
		if (fd == -1)
			return errno?:ESTALE;

		if (ioctl(fd, NS_GET_NSTYPE) != nstype)
			return EINVAL;

		DEBUG("opened existing %s namespace got filehandler %u\n",
			blobmsg_get_string(tb[OCI_LINUX_NAMESPACE_TYPE]),
			fd);

		*setns = fd;
	} else {
		opts.namespace |= nstype;
	}

	return 0;
};


enum {
	OCI_LINUX_UIDGIDMAP_CONTAINERID,
	OCI_LINUX_UIDGIDMAP_HOSTID,
	OCI_LINUX_UIDGIDMAP_SIZE,
	__OCI_LINUX_UIDGIDMAP_MAX,
};

static const struct blobmsg_policy oci_linux_uidgidmap_policy[] = {
	[OCI_LINUX_UIDGIDMAP_CONTAINERID] = { "containerID", BLOBMSG_TYPE_INT32 },
	[OCI_LINUX_UIDGIDMAP_HOSTID] = { "hostID", BLOBMSG_TYPE_INT32 },
	[OCI_LINUX_UIDGIDMAP_SIZE] = { "size", BLOBMSG_TYPE_INT32 },
};

static int parseOCIuidgidmappings(struct blob_attr *msg, bool is_gidmap)
{
	const char *map_format = "%d %d %d\n";
	struct blob_attr *tb[__OCI_LINUX_UIDGIDMAP_MAX];
	struct blob_attr *cur;
	int rem, len;
	char **mappings;
	char *map, *curstr;
	unsigned int cnt = 0;
	size_t totallen = 0;

	/* count number of mappings */
	blobmsg_for_each_attr(cur, msg, rem)
		cnt++;

	if (!cnt)
		return 0;

	/* allocate array for mappings */
	mappings = calloc(1 + cnt, sizeof(char*));
	if (!mappings)
		return ENOMEM;

	mappings[cnt] = NULL;

	cnt = 0;
	blobmsg_for_each_attr(cur, msg, rem) {
		blobmsg_parse(oci_linux_uidgidmap_policy, __OCI_LINUX_UIDGIDMAP_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (!tb[OCI_LINUX_UIDGIDMAP_CONTAINERID] ||
		    !tb[OCI_LINUX_UIDGIDMAP_HOSTID] ||
		    !tb[OCI_LINUX_UIDGIDMAP_SIZE])
			return EINVAL;

		/* write mapping line into allocated string */
		len = asprintf(&mappings[cnt++], map_format,
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_CONTAINERID]),
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_HOSTID]),
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_SIZE]));

		if (len < 0)
			return ENOMEM;

		totallen += len;
	}

	/* allocate combined mapping string */
	map = calloc(1 + totallen, sizeof(char));
	if (!map)
		return ENOMEM;

	map[0] = '\0';

	/* concatenate mapping strings into combined string */
	curstr = mappings[0];
	while (curstr) {
		strcat(map, curstr);
		free(curstr++);
	}
	free(mappings);

	if (is_gidmap)
		opts.gidmap = map;
	else
		opts.uidmap = map;

	return 0;
}

enum {
	OCI_DEVICES_TYPE,
	OCI_DEVICES_PATH,
	OCI_DEVICES_MAJOR,
	OCI_DEVICES_MINOR,
	OCI_DEVICES_FILEMODE,
	OCI_DEVICES_UID,
	OCI_DEVICES_GID,
	__OCI_DEVICES_MAX,
};

static const struct blobmsg_policy oci_devices_policy[] = {
	[OCI_DEVICES_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[OCI_DEVICES_PATH] = { "path", BLOBMSG_TYPE_STRING },
	[OCI_DEVICES_MAJOR] = { "major", BLOBMSG_TYPE_INT32 },
	[OCI_DEVICES_MINOR] = { "minor", BLOBMSG_TYPE_INT32 },
	[OCI_DEVICES_FILEMODE] = { "fileMode", BLOBMSG_TYPE_INT32 },
	[OCI_DEVICES_UID] = { "uid", BLOBMSG_TYPE_INT32 },
	[OCI_DEVICES_GID] = { "uid", BLOBMSG_TYPE_INT32 },
};

static mode_t resolve_devtype(char *tstr)
{
	if (!strcmp("c", tstr) ||
	    !strcmp("u", tstr))
		return S_IFCHR;
	else if (!strcmp("b", tstr))
		return S_IFBLK;
	else if (!strcmp("p", tstr))
		return S_IFIFO;
	else
		return 0;
}

static int parseOCIdevices(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_DEVICES_MAX];
	struct blob_attr *cur;
	int rem;
	size_t cnt = 0;
	struct mknod_args *tmp;

	blobmsg_for_each_attr(cur, msg, rem)
		++cnt;

	opts.devices = calloc(cnt + 1, sizeof(struct mknod_args *));

	cnt = 0;
	blobmsg_for_each_attr(cur, msg, rem) {
		blobmsg_parse(oci_devices_policy, __OCI_DEVICES_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[OCI_DEVICES_TYPE] ||
		    !tb[OCI_DEVICES_PATH])
			return ENODATA;

		tmp = calloc(1, sizeof(struct mknod_args));
		if (!tmp)
			return ENOMEM;

		tmp->mode = resolve_devtype(blobmsg_get_string(tb[OCI_DEVICES_TYPE]));
		if (!tmp->mode)
			return EINVAL;

		if (tmp->mode != S_IFIFO) {
			if (!tb[OCI_DEVICES_MAJOR] || !tb[OCI_DEVICES_MINOR])
				return ENODATA;

			tmp->dev = makedev(blobmsg_get_u32(tb[OCI_DEVICES_MAJOR]),
					   blobmsg_get_u32(tb[OCI_DEVICES_MINOR]));
		}

		if (tb[OCI_DEVICES_FILEMODE]) {
			if (~(S_IRWXU|S_IRWXG|S_IRWXO) & blobmsg_get_u32(tb[OCI_DEVICES_FILEMODE]))
				return EINVAL;

			tmp->mode |= blobmsg_get_u32(tb[OCI_DEVICES_FILEMODE]);
		} else {
			tmp->mode |= (S_IRUSR|S_IWUSR); /* 0600 */
		}

		tmp->path = strdup(blobmsg_get_string(tb[OCI_DEVICES_PATH]));

		if (tb[OCI_DEVICES_UID])
			tmp->uid = blobmsg_get_u32(tb[OCI_DEVICES_UID]);
		else
			tmp->uid = -1;

		if (tb[OCI_DEVICES_GID])
			tmp->gid = blobmsg_get_u32(tb[OCI_DEVICES_GID]);
		else
			tmp->gid = -1;

		DEBUG("read device %s (%s)\n", blobmsg_get_string(tb[OCI_DEVICES_PATH]), blobmsg_get_string(tb[OCI_DEVICES_TYPE]));
		opts.devices[cnt++] = tmp;
	}

	opts.devices[cnt] = NULL;

	return 0;
}

static int parseOCIsysctl(struct blob_attr *msg)
{
	struct blob_attr *cur;
	int rem;
	char *tmp, *tc;
	size_t cnt = 0;

	blobmsg_for_each_attr(cur, msg, rem) {
		if (!blobmsg_name(cur) || !blobmsg_get_string(cur))
			return EINVAL;

		++cnt;
	}

	if (!cnt)
		return 0;

	opts.sysctl = calloc(cnt + 1, sizeof(struct sysctl_val *));
	if (!opts.sysctl)
		return ENOMEM;

	cnt = 0;
	blobmsg_for_each_attr(cur, msg, rem) {
		opts.sysctl[cnt] = malloc(sizeof(struct sysctl_val));
		if (!opts.sysctl[cnt])
			return ENOMEM;

		/* replace '.' with '/' in entry name */
		tc = tmp = strdup(blobmsg_name(cur));
		while ((tc = strchr(tc, '.')))
			*tc = '/';

		opts.sysctl[cnt]->value = strdup(blobmsg_get_string(cur));
		opts.sysctl[cnt]->entry = tmp;

		++cnt;
	}

	opts.sysctl[cnt] = NULL;

	return 0;
}


enum {
	OCI_LINUX_CGROUPSPATH,
	OCI_LINUX_RESOURCES,
	OCI_LINUX_SECCOMP,
	OCI_LINUX_SYSCTL,
	OCI_LINUX_NAMESPACES,
	OCI_LINUX_DEVICES,
	OCI_LINUX_UIDMAPPINGS,
	OCI_LINUX_GIDMAPPINGS,
	OCI_LINUX_MASKEDPATHS,
	OCI_LINUX_READONLYPATHS,
	OCI_LINUX_ROOTFSPROPAGATION,
	__OCI_LINUX_MAX,
};

static const struct blobmsg_policy oci_linux_policy[] = {
	[OCI_LINUX_CGROUPSPATH] = { "cgroupsPath", BLOBMSG_TYPE_STRING },
	[OCI_LINUX_RESOURCES] = { "resources", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_SECCOMP] = { "seccomp", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_SYSCTL] = { "sysctl", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_NAMESPACES] = { "namespaces", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_DEVICES] = { "devices", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_UIDMAPPINGS] = { "uidMappings", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_GIDMAPPINGS] = { "gidMappings", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_MASKEDPATHS] = { "maskedPaths", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_READONLYPATHS] = { "readonlyPaths", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_ROOTFSPROPAGATION] = { "rootfsPropagation", BLOBMSG_TYPE_STRING },
};

static int parseOCIlinux(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_MAX];
	struct blob_attr *cur;
	int rem;
	int res = 0;
	char *cgpath;
	char cgfullpath[256] = "/sys/fs/cgroup";

	blobmsg_parse(oci_linux_policy, __OCI_LINUX_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_LINUX_NAMESPACES]) {
		blobmsg_for_each_attr(cur, tb[OCI_LINUX_NAMESPACES], rem) {
			res = parseOCIlinuxns(cur);
			if (res)
				return res;
		}
	}

	if (tb[OCI_LINUX_UIDMAPPINGS]) {
		res = parseOCIuidgidmappings(tb[OCI_LINUX_GIDMAPPINGS], 0);
		if (res)
			return res;
	}

	if (tb[OCI_LINUX_GIDMAPPINGS]) {
		res = parseOCIuidgidmappings(tb[OCI_LINUX_GIDMAPPINGS], 1);
		if (res)
			return res;
	}

	if (tb[OCI_LINUX_READONLYPATHS]) {
		blobmsg_for_each_attr(cur, tb[OCI_LINUX_READONLYPATHS], rem) {
			res = add_mount(NULL, blobmsg_get_string(cur), NULL, MS_BIND | MS_REC | MS_RDONLY, 0, NULL, 0);
			if (res)
				return res;
		}
	}

	if (tb[OCI_LINUX_MASKEDPATHS]) {
		blobmsg_for_each_attr(cur, tb[OCI_LINUX_MASKEDPATHS], rem) {
			res = add_mount((void *)(-1), blobmsg_get_string(cur), NULL, 0, 0, NULL, 0);
			if (res)
				return res;
		}
	}

	if (tb[OCI_LINUX_SYSCTL]) {
		res = parseOCIsysctl(tb[OCI_LINUX_SYSCTL]);
		if (res)
			return res;
	}

	if (tb[OCI_LINUX_SECCOMP]) {
		opts.ociseccomp = parseOCIlinuxseccomp(tb[OCI_LINUX_SECCOMP]);
		if (!opts.ociseccomp)
			return EINVAL;
	}

	if (tb[OCI_LINUX_DEVICES]) {
		res = parseOCIdevices(tb[OCI_LINUX_DEVICES]);
		if (res)
			return res;
	}

	if (tb[OCI_LINUX_CGROUPSPATH]) {
		cgpath = blobmsg_get_string(tb[OCI_LINUX_CGROUPSPATH]);
		if (cgpath[0] == '/') {
			if (strlen(cgpath) >= (sizeof(cgfullpath) - strlen(cgfullpath)))
				return E2BIG;

			strcat(cgfullpath, cgpath);
		} else {
			strcat(cgfullpath, "/containers/");
			strcat(cgfullpath, opts.name); /* should be container name rather than jail name */
			strcat(cgfullpath, "/");
			if (strlen(cgpath) >= (sizeof(cgfullpath) - strlen(cgfullpath)))
				return E2BIG;

			strcat(cgfullpath, cgpath);
		}
	} else {
		strcat(cgfullpath, "/containers/");
		strcat(cgfullpath, opts.name); /* should be container name rather than jail name */
		strcat(cgfullpath, "/");
		strcat(cgfullpath, opts.name); /* should be container instance name rather than jail name */
	}

	cgroups_init(cgfullpath);

	if (tb[OCI_LINUX_RESOURCES]) {
		res = parseOCIlinuxcgroups(tb[OCI_LINUX_RESOURCES]);
		if (res)
			return res;
	}

	return 0;
}

enum {
	OCI_VERSION,
	OCI_HOSTNAME,
	OCI_PROCESS,
	OCI_ROOT,
	OCI_MOUNTS,
	OCI_HOOKS,
	OCI_LINUX,
	OCI_ANNOTATIONS,
	__OCI_MAX,
};

static const struct blobmsg_policy oci_policy[] = {
	[OCI_VERSION] = { "ociVersion", BLOBMSG_TYPE_STRING },
	[OCI_HOSTNAME] = { "hostname", BLOBMSG_TYPE_STRING },
	[OCI_PROCESS] = { "process", BLOBMSG_TYPE_TABLE },
	[OCI_ROOT] = { "root", BLOBMSG_TYPE_TABLE },
	[OCI_MOUNTS] = { "mounts", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOKS] = { "hooks", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX] = { "linux", BLOBMSG_TYPE_TABLE },
	[OCI_ANNOTATIONS] = { "annotations", BLOBMSG_TYPE_TABLE },
};

static int parseOCI(const char *jsonfile)
{
	struct blob_attr *tb[__OCI_MAX];
	struct blob_attr *cur;
	int rem;
	int res;

	blob_buf_init(&ocibuf, 0);

	if (!blobmsg_add_json_from_file(&ocibuf, jsonfile)) {
		res=ENOENT;
		goto errout;
	}

	blobmsg_parse(oci_policy, __OCI_MAX, tb, blob_data(ocibuf.head), blob_len(ocibuf.head));

	if (!tb[OCI_VERSION]) {
		res=ENOMSG;
		goto errout;
	}

	if (strncmp("1.0", blobmsg_get_string(tb[OCI_VERSION]), 3)) {
		ERROR("unsupported ociVersion %s\n", blobmsg_get_string(tb[OCI_VERSION]));
		res=ENOTSUP;
		goto errout;
	}

	if (tb[OCI_HOSTNAME])
		opts.hostname = strdup(blobmsg_get_string(tb[OCI_HOSTNAME]));

	if (!tb[OCI_PROCESS]) {
		res=ENODATA;
		goto errout;
	}

	if ((res = parseOCIprocess(tb[OCI_PROCESS])))
		goto errout;

	if (!tb[OCI_ROOT]) {
		res=ENODATA;
		goto errout;
	}
	if ((res = parseOCIroot(jsonfile, tb[OCI_ROOT])))
		goto errout;

	if (!tb[OCI_MOUNTS]) {
		res=ENODATA;
		goto errout;
	}

	blobmsg_for_each_attr(cur, tb[OCI_MOUNTS], rem)
		if ((res = parseOCImount(cur)))
			goto errout;

	if (tb[OCI_LINUX] && (res = parseOCIlinux(tb[OCI_LINUX])))
		goto errout;

	if (tb[OCI_HOOKS] && (res = parseOCIhooks(tb[OCI_HOOKS])))
		goto errout;

	if (tb[OCI_ANNOTATIONS])
		opts.annotations = blob_memdup(tb[OCI_ANNOTATIONS]);

errout:
	blob_buf_free(&ocibuf);

	return res;
}

static int set_oom_score_adj(void)
{
	int f;
	char fname[32];

	if (!opts.set_oom_score_adj)
		return 0;

	snprintf(fname, sizeof(fname), "/proc/%u/oom_score_adj", jail_process.pid);
	f = open(fname, O_WRONLY | O_TRUNC);
	if (f == -1)
		return errno;

	dprintf(f, "%d", opts.oom_score_adj);
	close(f);

	return 0;
}


enum {
	OCI_STATE_CREATING,
	OCI_STATE_CREATED,
	OCI_STATE_RUNNING,
	OCI_STATE_STOPPED,
};

static int jail_oci_state = OCI_STATE_CREATED;
static void pipe_send_start_container(struct uloop_timeout *t);
static struct uloop_timeout start_container_timeout = {
	.cb = pipe_send_start_container,
};

static int handle_start(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	if (jail_oci_state != OCI_STATE_CREATED)
		return UBUS_STATUS_INVALID_ARGUMENT;

	uloop_timeout_add(&start_container_timeout);

	return UBUS_STATUS_OK;
}

static struct blob_buf bb;
static int handle_state(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	char *statusstr;

	switch (jail_oci_state) {
		case OCI_STATE_CREATING:
			statusstr = "creating";
			break;
		case OCI_STATE_CREATED:
			statusstr = "created";
			break;
		case OCI_STATE_RUNNING:
			statusstr = "running";
			break;
		case OCI_STATE_STOPPED:
			statusstr = "stopped";
			break;
		default:
			statusstr = "unknown";
	}

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "ociVersion", OCI_VERSION_STRING);
	blobmsg_add_string(&bb, "id", opts.name);
	blobmsg_add_string(&bb, "status", statusstr);
	if (jail_oci_state == OCI_STATE_CREATED ||
	    jail_oci_state == OCI_STATE_RUNNING)
		blobmsg_add_u32(&bb, "pid", jail_process.pid);

	blobmsg_add_string(&bb, "bundle", opts.ocibundle);

	if (opts.annotations)
		blobmsg_add_blob(&bb, opts.annotations);

	ubus_send_reply(ctx, req, bb.head);

	return UBUS_STATUS_OK;
}

enum {
	CONTAINER_KILL_ATTR_SIGNAL,
	__CONTAINER_KILL_ATTR_MAX,
};

static const struct blobmsg_policy container_kill_attrs[__CONTAINER_KILL_ATTR_MAX] = {
	[CONTAINER_KILL_ATTR_SIGNAL] = { "signal", BLOBMSG_TYPE_INT32 },
};

static int
container_handle_kill(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__CONTAINER_KILL_ATTR_MAX], *cur;
	int sig = SIGTERM;

	blobmsg_parse(container_kill_attrs, __CONTAINER_KILL_ATTR_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	cur = tb[CONTAINER_KILL_ATTR_SIGNAL];
	if (cur)
		sig = blobmsg_get_u32(cur);

	if (jail_oci_state == OCI_STATE_CREATING)
		return UBUS_STATUS_NOT_FOUND;

	if (kill(jail_process.pid, sig) == 0)
		return 0;

	switch (errno) {
	case EINVAL: return UBUS_STATUS_INVALID_ARGUMENT;
	case EPERM:  return UBUS_STATUS_PERMISSION_DENIED;
	case ESRCH:  return UBUS_STATUS_NOT_FOUND;
	}

	return UBUS_STATUS_UNKNOWN_ERROR;
}

static int
jail_writepid(pid_t pid)
{
	FILE *_pidfile;

	if (!opts.pidfile)
		return 0;

	_pidfile = fopen(opts.pidfile, "w");
	if (_pidfile == NULL)
		return errno;

	if (fprintf(_pidfile, "%d\n", pid) < 0) {
		fclose(_pidfile);
		return errno;
	}

	if (fclose(_pidfile))
		return errno;

	return 0;
}

static struct ubus_method container_methods[] = {
	UBUS_METHOD_NOARG("start", handle_start),
	UBUS_METHOD_NOARG("state", handle_state),
	UBUS_METHOD("kill", container_handle_kill, container_kill_attrs),
};

static struct ubus_object_type container_object_type =
	UBUS_OBJECT_TYPE("container", container_methods);

static struct ubus_object container_object = {
	.type = &container_object_type,
	.methods = container_methods,
	.n_methods = ARRAY_SIZE(container_methods),
};

static void post_main(struct uloop_timeout *t);
static struct uloop_timeout post_main_timeout = {
	.cb = post_main,
};
static int netns_fd;
static int pidns_fd;
#ifdef CLONE_NEWTIME
static int timens_fd;
#endif
static void post_create_runtime(void);
>>>>>>> 3019f50 (jail: leak less memory)
int main(int argc, char **argv)
{
	sigset_t sigmask;
	uid_t uid = getuid();
	char log[] = "/dev/log";
	char ubus[] = "/var/run/ubus.sock";
	int ch, i;

	if (uid) {
		ERROR("not root, aborting: %m\n");
		return EXIT_FAILURE;
	}

	umask(022);
	mount_list_init();
	init_library_search();
	cgroups_prepare();
	exit_from_child = false;

	while ((ch = getopt(argc, argv, OPT_ARGS)) != -1) {
		switch (ch) {
		case 'd':
			debug = atoi(optarg);
			break;
		case 'p':
			opts.namespace = 1;
			opts.procfs = 1;
			break;
		case 'o':
			opts.namespace = 1;
			opts.ronly = 1;
			break;
<<<<<<< HEAD
=======
		case 'f':
			opts.namespace |= CLONE_NEWUSER;
			break;
		case 'F':
			opts.namespace |= CLONE_NEWCGROUP;
			break;
		case 'R':
			opts.extroot = optarg;
			break;
>>>>>>> 3019f50 (jail: leak less memory)
		case 's':
			opts.namespace = 1;
			opts.sysfs = 1;
			break;
		case 'S':
			opts.seccomp = optarg;
			add_mount(optarg, 1, -1);
			break;
		case 'C':
			opts.capabilities = optarg;
			break;
		case 'c':
			opts.no_new_privs = 1;
			break;
		case 'n':
			opts.name = optarg;
			break;
		case 'h':
			opts.hostname = strdup(optarg);
			break;
		case 'r':
			opts.namespace = 1;
			add_path_and_deps(optarg, 1, 0, 0);
			break;
		case 'w':
			opts.namespace = 1;
			add_path_and_deps(optarg, 0, 0, 0);
			break;
		case 'u':
			opts.namespace = 1;
			add_mount(ubus, 0, -1);
			break;
		case 'l':
			opts.namespace = 1;
			add_mount(log, 0, -1);
			break;
		case 'U':
			opts.user = optarg;
			break;
		case 'G':
			opts.group = optarg;
			break;
		case 'E':
			opts.require_jail = 1;
			break;
<<<<<<< HEAD
		}
	}

=======
		case 'y':
			opts.console = 1;
			break;
		case 'J':
			opts.ocibundle = optarg;
			break;
		case 'i':
			opts.immediately = true;
			break;
		case 'P':
			opts.pidfile = optarg;
			break;
		}
	}

	if (opts.namespace && !opts.ocibundle)
		opts.namespace |= CLONE_NEWIPC | CLONE_NEWPID;

	/* those are filehandlers, so -1 indicates unused */
	opts.setns.pid = -1;
	opts.setns.net = -1;
	opts.setns.ns = -1;
	opts.setns.ipc = -1;
	opts.setns.uts = -1;
	opts.setns.user = -1;
	opts.setns.cgroup = -1;
#ifdef CLONE_NEWTIME
	opts.setns.time = -1;
#endif

	if (opts.capabilities && parseOCIcapabilities_from_file(&opts.capset, opts.capabilities)) {
		ERROR("failed to read capabilities from file %s\n", opts.capabilities);
		ret=-1;
		goto errout;
	}

	if (opts.ocibundle) {
		char *jsonfile;
		int ocires;

		asprintf(&jsonfile, "%s/config.json", opts.ocibundle);
		ocires = parseOCI(jsonfile);
		free(jsonfile);
		if (ocires) {
			ERROR("parsing of OCI JSON spec has failed: %s (%d)\n", strerror(ocires), ocires);
			ret=ocires;
			goto errout;
		}
	}

	if (opts.tmpoverlaysize && strlen(opts.tmpoverlaysize) > 8) {
		ERROR("size parameter too long: \"%s\"\n", opts.tmpoverlaysize);
		ret=-1;
		goto errout;
	}

>>>>>>> 3019f50 (jail: leak less memory)
	/* no <binary> param found */
	if (argc - optind < 1) {
		usage();
		ret=EXIT_FAILURE;
		goto errout;
	}
	if (!(opts.namespace||opts.capabilities||opts.seccomp)) {
		ERROR("Not using namespaces, capabilities or seccomp !!!\n\n");
		usage();
		ret=EXIT_FAILURE;
		goto errout;
	}
	DEBUG("Using namespaces(%d), capabilities(%d), seccomp(%d)\n",
		opts.namespace,
		opts.capabilities != 0,
		opts.seccomp != 0);

	/* allocate NULL-terminated array for argv */
	opts.jail_argv = calloc(1 + argc - optind, sizeof(char*));
	if (!opts.jail_argv)
		return EXIT_FAILURE;

	for (size_t s = optind; s < argc; s++)
		opts.jail_argv[s - optind] = strdup(argv[s]);

<<<<<<< HEAD
	if (opts.namespace && add_path_and_deps(*opts.jail_argv, 1, -1, 0)) {
		ERROR("failed to load dependencies\n");
		return -1;
=======
	if (opts.ocibundle) {
		char *objname;
		if (asprintf(&objname, "container.%s", opts.name) < 0) {
			ret=-ENOMEM;
			goto errout;
		}

		container_object.name = objname;
		ret = ubus_add_object(parent_ctx, &container_object);
		if (ret) {
			ERROR("Failed to add object: %s\n", ubus_strerror(ret));
			ret=-1;
			goto errout;
		}
	}

	/* deliberately not using 'else' on unrelated conditional branches */
	if (!opts.ocibundle) {
		/* allocate NULL-terminated array for argv */
		opts.jail_argv = calloc(1 + argc - optind, sizeof(char**));
		if (!opts.jail_argv) {
			ret=EXIT_FAILURE;
			goto errout;
		}
		for (size_t s = optind; s < argc; s++)
			opts.jail_argv[s - optind] = strdup(argv[s]);

		if (opts.namespace & CLONE_NEWUSER)
			get_jail_user(&opts.pw_uid, &opts.pw_gid, &opts.gr_gid);
	}

	if (!opts.extroot) {
		if (opts.namespace && add_path_and_deps(*opts.jail_argv, 1, -1, 0)) {
			ERROR("failed to load dependencies\n");
			ret=-1;
			goto errout;
		}
>>>>>>> 3019f50 (jail: leak less memory)
	}

	if (opts.namespace && opts.seccomp && add_path_and_deps("libpreload-seccomp.so", 1, -1, 1)) {
		ERROR("failed to load libpreload-seccomp.so\n");
		opts.seccomp = 0;
		if (opts.require_jail) {
			ret=-1;
			goto errout;
		}
	}

<<<<<<< HEAD
	if (opts.name)
		prctl(PR_SET_NAME, opts.name, NULL, NULL, NULL);

	uloop_init();
=======
	uloop_timeout_add(&post_main_timeout);
	uloop_run();

errout:
	if (opts.ocibundle)
		cgroups_free();

	free_opts(true);

	return ret;
}

static void post_main(struct uloop_timeout *t)
{
	if (apply_rlimits()) {
		ERROR("error applying resource limits\n");
		free_and_exit(EXIT_FAILURE);
	}

	if (opts.name)
		prctl(PR_SET_NAME, opts.name, NULL, NULL, NULL);

	if (pipe(&pipes[0]) < 0 || pipe(&pipes[2]) < 0)
		free_and_exit(-1);
>>>>>>> 3019f50 (jail: leak less memory)

	sigfillset(&sigmask);
	for (i = 0; i < _NSIG; i++) {
		struct sigaction s = { 0 };

		if (!sigismember(&sigmask, i))
			continue;
		if ((i == SIGCHLD) || (i == SIGPIPE) || (i == SIGSEGV))
			continue;

		s.sa_handler = jail_handle_signal;
		sigaction(i, &s, NULL);
	}

	if (opts.namespace) {
		add_mount("/dev/full", 0, -1);
		add_mount("/dev/null", 0, -1);
		add_mount("/dev/urandom", 0, -1);
		add_mount("/dev/zero", 0, -1);

		if (opts.user || opts.group) {
			add_mount("/etc/passwd", 0, -1);
			add_mount("/etc/group", 0, -1);
		}

		int flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | SIGCHLD;
		if (opts.hostname)
			flags |= CLONE_NEWUTS;
		jail_process.pid = clone(exec_jail, child_stack + STACK_SIZE, flags, NULL);
	} else {
		jail_process.pid = fork();
	}

	if (jail_process.pid > 0) {
		/* parent process */
		uloop_process_add(&jail_process);
		uloop_run();
		if (jail_running) {
			DEBUG("uloop interrupted, killing jail process\n");
			kill(jail_process.pid, SIGTERM);
			uloop_timeout_set(&jail_process_timeout, 1000);
			uloop_run();
		}
		uloop_done();
		free_opts(true);
		return free_and_exit(jail_return_code);
	} else if (jail_process.pid == 0) {
		/* fork child process */
		return free_and_exit(exec_jail(NULL));
	} else {
		ERROR("failed to clone/fork: %m\n");
		return free_and_exit(EXIT_FAILURE);
	}
}
