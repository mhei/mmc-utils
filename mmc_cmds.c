/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <uuid/uuid.h>
#include <ctype.h>

#include "mmc.h"
#include "mmc_cmds.h"

int read_extcsd(int fd, __u8 *ext_csd)
{
	int ret = 0;
	struct mmc_ioc_cmd idata;
	memset(&idata, 0, sizeof(idata));
	memset(ext_csd, 0, sizeof(__u8) * 512);
	idata.write_flag = 0;
	idata.opcode = MMC_SEND_EXT_CSD;
	idata.arg = 0;
	idata.flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;
	idata.blksz = 512;
	idata.blocks = 1;
	mmc_ioc_cmd_set_data(idata, ext_csd);

	ret = ioctl(fd, MMC_IOC_CMD, &idata);
	if (ret)
		perror("ioctl");

	return ret;
}

int write_extcsd_value(int fd, __u8 index, __u8 value)
{
	int ret = 0;
	struct mmc_ioc_cmd idata;

	memset(&idata, 0, sizeof(idata));
	idata.write_flag = 1;
	idata.opcode = MMC_SWITCH;
	idata.arg = (MMC_SWITCH_MODE_WRITE_BYTE << 24) |
			(index << 16) |
			(value << 8) |
			EXT_CSD_CMD_SET_NORMAL;
	idata.flags = MMC_RSP_SPI_R1B | MMC_RSP_R1B | MMC_CMD_AC;

	ret = ioctl(fd, MMC_IOC_CMD, &idata);
	if (ret)
		perror("ioctl");

	return ret;
}

int do_read_extcsd(int nargs, char **argv)
{
	__u8 ext_csd[512];
	int fd, ret;
	char *device;

	CHECK(nargs != 2, "Usage: mmc </path/to/mmcblkX>\n", exit(1));

	device = argv[1];

	fd = open(device, O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	ret = read_extcsd(fd, ext_csd);
	if (ret) {
		fprintf(stderr, "Could not read EXT_CSD from %s\n", device);
		exit(1);
	}

	printf("Power ro locking: ");
	if (ext_csd[EXT_CSD_BOOT_WP] & EXT_CSD_BOOT_WP_B_PWR_WP_DIS)
		printf("not possible\n");
	else
		printf("possible\n");
        
	printf("Permanent ro locking: ");
	if (ext_csd[EXT_CSD_BOOT_WP] & EXT_CSD_BOOT_WP_B_PERM_WP_DIS)
		printf("not possible\n");
	else
		printf("possible\n");
        
	printf("ro lock status: ");
	if (ext_csd[EXT_CSD_BOOT_WP] & EXT_CSD_BOOT_WP_B_PWR_WP_EN)
		printf("locked until next power on\n");
	else if (ext_csd[EXT_CSD_BOOT_WP] &
		 EXT_CSD_BOOT_WP_B_PERM_WP_EN)
		printf("locked permanently\n");
	else
		printf("not locked\n");

	return ret;
}

int do_write_extcsd(int nargs, char **argv)
{
	__u8 ext_csd[512], value;
	int fd, ret;
	char *device;

	if (nargs != 2) {
		fprintf (stderr, "Usage: %s </path/to/mmcblkX>\n",
								argv[0]);
		exit (1);
	}
	device = argv[1];

	fd = open(device, O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	ret = read_extcsd(fd, ext_csd);
	if (ret) {
		fprintf(stderr, "Could not read EXT_CSD from %s\n", device);
		exit(1);
	}

	value = ext_csd[EXT_CSD_BOOT_WP] |
		EXT_CSD_BOOT_WP_B_PWR_WP_EN;
	ret = write_extcsd_value(fd, EXT_CSD_BOOT_WP, value);
	if (ret) {
		fprintf(stderr, "Could not write 0x%02x to "
			"EXT_CSD[%d] in %s\n",
			value, EXT_CSD_BOOT_WP, device);
		exit(1);
	}

	return ret;
}
