# HK-51 IRC Bot
# Copyright (C) 2018-2019 - Matthew Hoops (clone2727)
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

import re

import sopel

# TODO: Allow for commands to work in private messages without the nickname prefix

def _rule_wrapper(rule, query=False):
	rule = r'^$nickname[:,]?\s+({})'.format(rule)

	if query:
		rule += r'\??'

	return sopel.module.rule(rule)

def nickname_command(command):
	return _rule_wrapper(command)

def nickname_query(query):
	return _rule_wrapper(query, True)

def nickname_commands(*command_list):
	return nickname_command('|'.join([re.escape(x) for x in command_list]))
