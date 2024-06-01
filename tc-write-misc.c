#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

char *signature = "boot-recovery";

/* Recovery Message */
typedef struct _recovery_message {
	char command[32];
	char status[32];
	char recovery[1024];
} recovery_message;

const char *_default_cmd = "boot-recovery";

int main(int argc, char *argv[])
{
	int fd;
	int ret = -1;
	char *cmd;

	if (argc > 1)
	{
		cmd = argv[1];
	}
	else
	{
		cmd = _default_cmd;
	}

	/* misc Partition - open dev*/
	//fd = open("/dev/disk/by-partlabel/misc", O_RDWR|O_NDELAY);
	fd = open("/dev/block/platform/bdm/by-name/misc", O_RDWR|O_NDELAY);

	if (fd != -1)
	{
		recovery_message *msg;
		msg = (recovery_message *)malloc(sizeof(recovery_message));
		memset(msg, 0, sizeof(recovery_message));
		strncpy(msg->command, cmd, sizeof(msg->command));

		write(fd, msg, sizeof(recovery_message));
		//fprintf(stderr, "write '%s' to /dev/disk/by-partlabel/misc finished\n", cmd);
		fprintf(stderr, "write '%s' to /dev/block/platform/bdm/by-name/misc finished\n", cmd);

		close(fd);
		ret = 0;
	}
	else
	{
		//fprintf(stderr, "open /dev/disk/by-partlabel/misc failed\n");
		fprintf(stderr, "open /dev/block/platform/bdm/by-name/misc failed\n");
	}

	return ret;
}

