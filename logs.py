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

import sopel

@sopel.module.event('JOIN')
@sopel.module.rule('.*')
def log_join(bot, trigger):
	print('{} has joined {}'.format(trigger.nick, trigger.sender))

@sopel.module.event('PART')
@sopel.module.rule('.*')
def log_part(bot, trigger):
	print('{} has parted {}: \'{}\''.format(trigger.nick, trigger.sender, trigger))

@sopel.module.event('QUIT')
@sopel.module.rule('.*')
def log_quit(bot, trigger):
	print('{} has quit: \'{}\''.format(trigger.nick, trigger))

@sopel.module.event('KICK')
@sopel.module.rule('.*')
def log_kick(bot, trigger):
	print('{} has been kicked from {} by {}'.format(trigger.args[1], trigger.nick, trigger.sender))

@sopel.module.event('TOPIC')
@sopel.module.rule('.*')
def log_topic_change(bot, trigger):
	print('{} has changed the topic in {} to \'{}\''.format(trigger.nick, trigger.sender, trigger))

@sopel.module.event('NICK')
@sopel.module.rule('.*')
def log_nick_change(bot, trigger):
	print('{} is now known as {}'.format(trigger.nick, trigger))

'''
@sopel.module.event('AWAY')
@sopel.module.rule('.*')
def log_away_change(bot, trigger):
	print('args[1] = {}'.format(trigger.args[1]))
	if trigger.args[1]:
		print('{} is now away'.format(trigger.nick))
	else:
		print('{} is no longer away'.format(trigger.nick))
'''

@sopel.module.rule('.*')
def log_normal(bot, trigger):
	if trigger.tags.get('intent', '') == 'ACTION':
		print('{} has done some kind of action'.format(trigger.nick))
	else:
		print('{} has said something'.format(trigger.nick))
	print('Trigger: ' + str(dir(trigger)))
	print('Raw: ' + str(trigger))
	print('Host: ' + str(trigger.host))
	print('Hostmask: ' + str(trigger.hostmask))
	print('Sender: ' + str(trigger.sender))
