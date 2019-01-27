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

import http.server
import json
import ssl
import threading

_message_hook = None


class GitHubHook:
	def on_messages(self, messages):
		raise NotImplementedError


class StdOutHook(GitHubHook):
	def on_messages(self, messages):
		for message in messages:
			print(message)


class BotHook(GitHubHook):
	def __init__(self, bot, channels):
		self._bot = bot
		self._channels = channels

	def on_messages(self, messages):
		# Figure out the recipients
		recipients = sorted([channel for channel in self._bot.channels.keys() if not self._channels or channel in self._channels])

		for recipient in recipients:
			for message in messages:
				self._bot.say(message, recipient)


class GitHubRequestHandler(http.server.BaseHTTPRequestHandler):
	def do_POST(self):
		# Pull in some needed headers
		#delivery_guid = self.headers.get('X-Github-Delivery')
		#hex_digest = self.headers.get('X-Hub-Signature')
		event_type = self.headers.get('X-GitHub-Event')
		content_len = int(self.headers.get('Content-Length'))

		# Parse the payload as json
		post_body = self.rfile.read(content_len)
		# TODO: Check digest against request
		request = json.loads(post_body)

		'''
		print('GOT REQUEST {0}'.format(event_type))
		print(request)
		'''

		# Deal with types we care about
		if event_type == 'issues':
			self._on_issues(request)
		elif event_type == 'pull_request':
			self._on_pull_request(request)
		elif event_type == 'push':
			self._on_push(request)

		# Accept the message
		self.send_response(200)
		self.send_header('Content-type', 'text.html')
		self.end_headers()
		self.wfile.write(bytes('<html><head><title>Success</title></head><body></body></html>', 'utf-8'))

	def _on_issues(self, request):
		action = request['action']

		# If it's an action we don't care about, just ignore it
		if action not in ('opened', 'closed', 'reopened'):
			return

		# Fetch a bunch of fields that we need
		issue = request['issue']
		url = issue['html_url']
		number = issue['number']
		title = issue['title']
		repo = request['repository']
		repo_name = repo['name']
		sender = request['sender']
		login = sender['login']

		# Format the message
		message = '[{0}] {1} {2} issue #{3}: {4} {5}'.format(
			repo_name,
			login,
			action,
			number,
			title,
			url)

		self._on_messages([message])

	def _on_pull_request(self, request):
		action = request['action']

		# If it's an action we don't care about, just ignore it
		if action not in ('opened', 'closed', 'reopened'):
			return

		# Fetch a bunch of fields that we need
		number = request['number']
		pull_request = request['pull_request']
		url = pull_request['html_url']
		title = pull_request['title']
		head = pull_request['head']
		head_ref = head['ref']
		base = pull_request['base']
		base_ref = base['ref']
		repo = request['repository']
		repo_name = repo['name']
		user = pull_request['user']
		login = user['login']

		# Format the message
		message = '[{0}] {1} {2} pull request #{3}: {4} ({5}..{6}) {7}'.format(
			repo_name,
			login,
			action,
			number,
			title,
			base_ref,
			head_ref,
			url)

		self._on_messages([message])

	def _on_push(self, request):
		ref = request['ref']
		compare_url = request['compare']
		commits = request['commits']
		repository = request['repository']
		repo_name = repository['name']
		repo_url = repository['html_url']
		sender = request['sender']
		user = sender['login']
		ref_type = ref.split('/', 2)[1]
		branch = ref.split('/', 2)[2]
		created = request['created']
		deleted = request['deleted']
		forced = request['forced']
		before = request['before']
		after = request['after']
		size = len(request['commits'])
		base_ref = request['base_ref']

		if base_ref:
			top_message = '[{0}] {1} merged {2} into {3}: {4}'.format(
				repo_name,
				user,
				base_ref.split('/', 2)[2],
				branch,
				compare_url)
		elif created:
			if ref_type == 'tags':
				top_message = '[{0}] {1} tagged {2} at {3}: {4}'.format(
					repo_name,
					user,
					branch,
					after[:7],
					compare_url)
			else:
				top_message = '[{0}] {1} created {2} (+{3} new commits): {4}'.format(
					repo_name,
					user,
					branch,
					size,
					compare_url)
		elif deleted:
			# TODO: API doesn't seem to provide the commit URL directly
			top_message = '[{0}] {1} deleted {2} at {3}: {4}'.format(
				repo_name,
				user,
				branch,
				before[:7],
				repo_url + '/commit/' + before[:7])
		elif forced:
			# TODO: API doesn't seem to provide the commits URL directly
			top_message = '[{0}] {1} force-pushed {2} from {3} to {4}: {5}'.format(
				repo_name,
				user,
				branch,
				before[:7],
				after[:7],
				repo_url + '/commits/' + branch)
		else:
			top_message = '[{0}] {1} pushed {2} new commits to {3}: {4}'.format(
				repo_name,
				user,
				size,
				branch,
				compare_url)

		messages = [top_message]

		# Truncate the commits to the first three and print them
		for commit in commits[:3]:
			commit_hash = commit['id']
			author = commit['author']
			author_name = author['name']
			message = commit['message']
			messages.append('{0}/{1} {2} {3}: {4}'.format(repo_name, branch, commit_hash[:7], author_name, message))

		self._on_messages(messages)

	def _on_messages(self, messages):
		hook = _message_hook
		if hook:
			hook.on_messages(messages)


def _create_server(host, port, cert_file=None, hook=None):
	# Assign the hook
	global _message_hook
	_message_hook = hook

	# Create the basic server
	server = http.server.HTTPServer((host, port), GitHubRequestHandler)

	# Wrap in TLS if we have a cert
	if cert_file:
		# Create a client-authenticating context
		context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
		context.load_cert_chain(cert_file)

		# Wrap the socket
		server.socket = context.wrap_socket(server.socket, server_side=True)

	return server


def init_bot_webhook(host, port, bot, channels=[], cert_file=None):
	# Create the server
	server = _create_server(host, port, hook=BotHook(bot, channels), cert_file=cert_file)

	# Spawn a thread to handle the requests
	thread = threading.Thread(target=server.serve_forever)
	thread.start()


# Debug code for when running as main
if __name__ == '__main__':
	# Pull info off the command line
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('--host', help='Host to bind to', default='127.0.0.1')
	parser.add_argument('--port', help='Port to listen on', type=int, default=80)
	parser.add_argument('--cert-file', help='Certificate file')
	args = parser.parse_args()

	# Create the server
	server = _create_server(args.host, args.port, hook=StdOutHook(), cert_file=args.cert_file)

	# Listen until someone sends in a SIGINT
	server.serve_forever()
