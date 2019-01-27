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

import datetime
import sopel
import sopel.config.types
import sopel.tools
import sys

# Import all the jokes
from .jokes import *

# TODO: Import the logger
#from .logs import *

# Import the GitHub hook
from .github import init_bot_webhook

class HK51Section(sopel.config.types.StaticSection):
	host = sopel.config.types.ValidatedAttribute('github_host', default=None)
	port = sopel.config.types.ValidatedAttribute('github_port', default=None, parse=int)
	channels = sopel.config.types.ListAttribute('github_channels', default=[])

def setup(bot):
	# Define the section
	config = bot.config
	config.define_section('hk51', HK51Section)

	host = config.hk51.host
	port = config.hk51.port
	channels = config.hk51.channels

	if host and port:
		init_bot_webhook(host, port, bot, channels=channels)

# TODO: Enable once the new logs replacement is finished
'''
@sopel.module.nickname_commands('seen')
def seen(bot, trigger):
	# Pull the nick
	nick = trigger.group(2)
	if nick:
		nick = nick.strip().rstrip('?')
	if not nick:
		bot.say('Mockery: I cannot respond without a nick.')
		return

	# Check if the user is the bot
	nick_identifier = sopel.tools.Identifier(nick)
	if nick_identifier == bot.nick:
		bot.say('Mockery: I am {}!'.format(bot.nick))
		return

	# Check if the sender is the bot
	if nick_identifier == trigger.nick:
		bot.say('Mockery: You are {}!'.format(trigger.nick))
		return

	# See if the nick is in any of the current channels	
	if nick_identifier in bot.users:
		user = bot.users[nick_identifier]

		# If the user is in the current channel, mock them
		if trigger.sender in user.channels:
			bot.say('Mockery: {} is right here!'.format(nick))
			return

		# Figure out how to write the channel list
		channel_list = sorted(user.channels.iterkeys())
		if len(channel_list) == 1:
			channel_text = channel_list[0]
		elif len(channel_list) == 2:
			channel_text = channel_list[0] + ' and ' + channel_list[1]
		else:
			channel_text = ', '.join(channel_list[:-1]) + ', and ' + channel_list[-1]

		bot.say('Statement: {} is in {}'.format(nick, channel_text))
		return

	timestamp = bot.db.get_nick_value(nick, 'seen_timestamp')
	if timestamp:
		# We have a timestamp! Give a reasonable response.

		# FIXME: strftime uses the current locale; %A should be in English to match the bot's language
		# TODO: Convert to the user's time zone
		# TODO: Write a time diff too
		# TODO: Write the action/message they gave
		saw = datetime.datetime.utcfromtimestamp(timestamp)
		bot.say('Answer: I last saw {} on {}, {} at {} UTC.'.format(nick, saw.strftime('%A'), saw.strftime('%Y-%m-%d'), saw.strftime('%H:%M:%S')))
	else:
		# We could not find the user
		bot.say("Answer: I have not seen the meatbag named {}.".format(nick))
'''

@sopel.module.nickname_commands('die')
def die(bot, trigger):
	if trigger.owner:
		bot.quit('Statement: Shutting down, master.')
	else:
		bot.say('Mocking Statement: You are a meatbag, not my master, {}.'.format(trigger.nick))

