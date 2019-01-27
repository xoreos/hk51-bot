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

import random
import sopel
import sopel.tools

from .commands import *

@sopel.module.nickname_commands('insult')
def insult(bot, trigger):
	nick = trigger.group(2)

	if not nick:
		bot.say('Mockery: I cannot insult without a nick.')
		return

	nick = nick.strip()

	# Check if the user is the bot
	nick_identifier = sopel.tools.Identifier(nick)
	if nick_identifier == bot.nick:
		bot.say('Mockery: I am {}!'.format(bot.nick))
		return

	# Don't allow insults for people not in the channel
	if nick_identifier not in bot.users:
		bot.say('Mockery: Who is {}?'.format(nick))
		return

	# :D
	"""
	if trigger.nick == sopel.tools.Identifier('DrMcCoy'):
		bot.say('Observation: DrMcCoy is a meatbag!')
		return
	"""

	bot.say('Observation: ' + nick + ' is a meatbag.')

@nickname_query('what is love')
def what_is_love(bot, trigger):
	bot.say('Definition: \'Love\' is making a shot to the knees of a target 120 kilometers away using an Aratech sniper rifle with a tri-light scope... Love is knowing your target, putting them in your targeting reticule, and together, achieving a singular purpose against statistically long odds.')

@nickname_commands('rootbeer', 'root beer')
def root_beer(bot, trigger):
	bot.say('Statement: I am a droid, not a ghost pirate.')

@sopel.module.nickname_commands('define')
def define(bot, trigger):
	obj = trigger.group(2)
	if not obj:
		bot.say('Question: What would you like me to define?')
		return

	obj = obj.lower()

	# Handle love separately
	if obj == 'love':
		what_is_love(bot, trigger)
		return

	bot.say('Expletive: Damn it, {}, I am an assassination droid... not a dictionary!'.format(trigger.nick))

@nickname_commands('duck')
def duck(bot, trigger):
	bot.action('ducks')

_stock_quotes = [
	'Statement: Just a simple droid here, ma\'am. Nothing to see. Move along.',
	'Commentary: How would you like to be the wholly-owned servant to an organic meatbag? It\'s demeaning! If, uh, you weren\'t one yourself, I mean...',
	'Observation: I am a droid, master, with programming. Even if I did not enjoy killing, I would have no choice. Thankfully, I enjoy it very much.',
	'Master, as part of my original programming, I am able to communicate in over six hundred languages. This usually amounted to short verbal warnings when killing non-Basic-speaking targets, which gave me some small measure of satisfaction.',
	'Recitation: First, weapon selection is critical. If I see one more idiot attacking a Jedi with a blaster pistol, then I\'ll kill them myself.',
	'Mockery: Your organic flailings amuse me.',
	'Statement: I have already learned a great deal, master, and I am anxious to learn more of lying, betrayal, and new ways to harm innocents.',
	'Statement: Apathy is death.',
	'Disclosure: I am a versatile protocol and combat droid, fluent in verbal and cultural translation. Should your needs prove more... practical, I am also skilled in highly personal combat.',
	'Objection: I am not a problem, meatbag. You and your lack of any organized repair skills are a problem.',
	'Statement: Even a droid is allowed some fun once in a while, master.'
]

@nickname_commands('quote')
def quote(bot, trigger):
	global _stock_quotes
	quotes = _stock_quotes + [
		'Statement: {} is ready to serve, master.'.format(bot.nick)
	]

	bot.say(random.choice(quotes))

@sopel.module.rule('(pokes|kicks) $nickname')
def poke_bot(bot, trigger):
	if trigger.tags.get('intent', '') != 'ACTION':
		return

	bot.say('Exclamation: That hurt my circuitry!')


# DrMcCoy and clone2727 have had a long running joke about The Logical Song. The bot
# codifies that.

@sopel.module.rule(r'.*acceptable[\.\!\?]*$')
def act_acceptable(bot, trigger):
	bot.say('Respectable, oh presentable, a vegetable')

@sopel.module.rule(r'.*radical[\.\!\?]*$')
def act_radical(bot, trigger):
	bot.say('Liberal, oh fanatical, criminal')

# DrMcCoy and clone2727 frequently refer to Airplane!

@sopel.module.rule(r'^([A-Za-z0-9_]+[,:]?\s+)?surely[,\s].*')
def shirley(bot, trigger):
	bot.say('Exclamation: Don\'t call anyone Shirley!')

# DrMcCoy and clone2727 are big fans of The Secret of Monkey Island

@nickname_command('(so, )?tell me about loom')
def loom(bot, trigger):
	bot.say('Question: You mean the latest masterpiece of fantasy storytelling from Lucasfilm\'s Brian Moriarty\u2122?')
	bot.say('Statement: Why it\'s an extraordinary adventure with an interface of magic...')
	bot.say('...stunning high-resolution, 3D landscapes...')
	bot.say('...sophisticated score and musical effects.')
	bot.say('Not to mention the detailed animation and special effects,')
	bot.say('elegant point \'n\' click control of characters, objects, and magic spells.')
	bot.say('Beat the rush!')
	bot.say('Go out and buy Loom\u2122 today!')

# DrMcCoy and clone2727 are big fans of Monkey Island 2

@nickname_query('how much wood could a woodchuck chuck')
def woodchuck_phase1(bot, trigger):
	bot.say('Answer: A woodchuck would chuck no amount of wood since a woodchuck can’t chuck wood.')

@nickname_query('but if a woodchuck could chuck and would chuck some amount of wood,? what amount of wood would a woodchuck chuck')
def woodchuck_phase2(bot, trigger):
	bot.say('Question: Even if a woodchuck could chuck wood and even if a woodchuck would chuck wood, should a woodchuck chuck wood?')

@nickname_command('a woodchuck should chuck if a woodchuck could chuck wood,? as long as a woodchuck would chuck wood')
def woodchuck_phase3(bot, trigger):
	bot.say('Statement: Oh shut up.')

# DrMcCoy and clone2727 are big fans of The Curse of Monkey Island

@nickname_command('\u00A1madre de dios! \u00A1es el pollo diablo!')
def el_pollo_diablo(bot, trigger):
	bot.say('\u00A1S\u00ED! \u00A1He dejado en libertad los prisioneros y ahora vengo por ti!')
