/**
 * bnotify - Notify the userspace that the process is blocked.
 * Copyright (C) 2013 Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __BNOTIFY_H
#define __BNOTIFY_H

#include <linux/ioctl.h>

#define BNOTIFY_IOC_MAGIC	'x'
#define BNOTIFY_IOCADD		_IO(BNOTIFY_IOC_MAGIC, 1)

#endif /* __BNOTIFY_H */
