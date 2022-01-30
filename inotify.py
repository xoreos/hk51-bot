# HK-51 IRC Bot
# Copyright (C) 2018-2022 - Matthew Hoops (clone2727)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

import ctypes
import os
import sys


# Validate that we only work on Linux; makes it clear instead of a later-on error.
if sys.platform != 'linux':
	raise ImportError('Only works on Linux')


class _header(ctypes.Structure):
	"""The header of inotify_event, minus the variable name."""

	_fields_ = [
		('wd', ctypes.c_int),
		('mask', ctypes.c_uint32),
		('cookie', ctypes.c_uint32),
		('len', ctypes.c_uint32)
	]


# Store the header size as a constant so we don't need to recalculate it.
_HEADER_SIZE = ctypes.sizeof(_header)


# Calculate the size of each read call from inotify.
_READ_SIZE = _HEADER_SIZE + 255 + 1


def _fd_errcheck(result, func, arguments):
	"""Treat a C function result as an fd, handling -1 as an error."""
	if result == -1:
		error = ctypes.get_errno()
		raise OSError(error, os.strerror(error))

	return result


def _nonzero_errcheck(result, func, arguments):
	"""Treat a C function result as 0=success, handling everything else as an error."""
	if result != 0:
		error = ctypes.get_errno()
		raise OSError(error, os.strerror(error))

	return None


class _StringWrapper:
	"""Auto-wrap python strings into char* parameters, treating strings as UTF-8."""
	@classmethod
	def from_param(cls, value):
		"""Emulate the ctypes._CData.from_param class function to wrap strings."""

		if isinstance(value, str):
			value = value.encode('UTF-8')

		return ctypes.c_char_p.from_param(value)


# Import the C library.
_libc = ctypes.CDLL('libc.so.6')

# Load the inotify_init1 function
inotify_init1 = _libc.inotify_init1
inotify_init1.restype = ctypes.c_int
inotify_init1.argtypes = [ctypes.c_int]
inotify_init1.errcheck = _fd_errcheck

# Load the inotify_add_watch function
inotify_add_watch = _libc.inotify_add_watch
inotify_add_watch.restype = ctypes.c_int
inotify_add_watch.argtypes = [ctypes.c_int, _StringWrapper, ctypes.c_uint32]
inotify_add_watch.errcheck = _fd_errcheck

# Load the inotify_rm_watch function
inotify_rm_watch = _libc.inotify_rm_watch
inotify_rm_watch.restype = ctypes.c_int
inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
inotify_rm_watch.errcheck = _nonzero_errcheck


# inotify_add_watch mask flags.
IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_CLOSE = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_MOVE = IN_MOVED_FROM | IN_MOVED_TO
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800

# Other events returned by the kernel.
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000

# Helper events.
IN_CLOSE = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE
IN_MOVE = IN_MOVED_FROM | IN_MOVED_TO

# Special flags.
IN_ONLYDIR = 0x01000000
IN_DONT_FOLLOW = 0x02000000
IN_EXCL_UNLINK = 0x04000000
IN_MASK_CREATE = 0x10000000
IN_MASK_ADD = 0x20000000
IN_ISDIR = 0x40000000
IN_ONESHOT = 0x80000000

# All events a program can wait on.
IN_ALL_EVENTS = \
	IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | \
	IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | \
	IN_MOVED_TO | IN_CREATE | IN_DELETE | \
	IN_DELETE_SELF | IN_MOVE_SELF


# inotify_init1 flags
IN_CLOEXEC = 0x00080000
IN_NONBLOCK = 0x00000800


class _Watcher:
	"""Object returned by Manager.add_watch to manage the watch."""

	def __init__(self, pathname, mask, close, callback=None):
		self.pathname = pathname
		self.mask = mask
		self.close = close
		self.callback = callback

	def on_event(self, mask, cookie, name):
		callback = self.callback
		if callback:
			callback(mask, cookie, name)


class Manager:
	"""Simple manager wrapper for inotify calls."""

	def __init__(self):
		self._fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK)
		self._callbacks = {}

	def close(self):
		try:
			fd = self._fd
		except AttributeError:
			return

		os.close(fd)
		del self._fd

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, traceback):
		self.close()

	def fileno(self):
		"""Return the file descriptor associated with this instance."""
		return self._fd

	def on_event(self, fd):
		"""Handle a read event."""
		buf = os.read(fd, _READ_SIZE)
		pos = 0

		while pos < len(buf):
			header = _header.from_buffer_copy(buf[pos:pos + _HEADER_SIZE])
			pos += _HEADER_SIZE

			if header.len:
				name = buf[pos:pos + header.len].split(b'\0', 1)[0].decode('UTF-8')
				pos += header.len
			else:
				name = ''

			try:
				callback = self._callbacks[int(header.wd)]
			except KeyError as ex:
				return

			callback(header.mask, header.cookie, name)

	def add_watch(self, pathname, mask, callback=None):
		"""Add a watch on a path, returning an object capable of managing it."""
		wd = inotify_add_watch(self._fd, pathname, mask)
		try:
			watcher = _Watcher(pathname, mask, lambda: self._rm_watch(wd), callback)
			self._callbacks[wd] = watcher.on_event
			return watcher
		except:
			self._rm_watch(wd)
			raise

	def _rm_watch(self, wd):
		try:
			del self._callbacks[wd]
		except KeyError:
			pass

		inotify_rm_watch(self._fd, wd)
