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

import hmac
import http.server
import json
import shutil
import ssl
import tempfile
import threading

_message_hook = None
_secret = None


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


class HTTPError(Exception):
	def __init__(self, code, text):
		super().__init__('{0}: {1}'.format(code, text))
		self.code = code
		self.text = text


class BadRequestError(HTTPError):
	def __init__(self):
		super().__init__(400, 'Bad Request')


class ForbiddenError(HTTPError):
	def __init__(self):
		super().__init__(403, 'Forbidden')


class GitHubRequestHandler(http.server.BaseHTTPRequestHandler):
	def do_POST(self):
		try:
			self._handle_post()
		except HTTPError as ex:
			code = ex.code
			text = ex.text
		except Exception as ex:
			# Other exception we don't know about: it's our internal error
			code = 500
			text = 'Internal Error'
		else:
			code = 200
			text = 'Success'

		# Send the message back
		self.send_response(code)
		self.send_header('Content-type', 'text/plain')
		self.end_headers()
		self.wfile.write(text.encode('utf-8'))

	def _handle_post(self):
		# Pull in some needed headers
		#delivery_guid = self.headers.get('X-Github-Delivery')
		check_digest = self.headers.get('X-Hub-Signature')
		event_type = self.headers.get('X-GitHub-Event')
		content_type = self.headers.get('Content-Type')
		content_len = int(self.headers.get('Content-Length'))

		# Make sure we have a JSON request
		if content_type != 'application/json':
			raise BadRequestError()

		# Verify the content
		post_body = self.rfile.read(content_len)
		if _secret:
			# Ensure that we actually have the field in the header
			if not check_digest:
				raise BadRequestError()

			# Only accept sha1 for now
			if not check_digest.startswith('sha1='):
				raise BadRequestError()

			# Strip off the header
			check_digest = check_digest[5:]

			# Calculate the correct digest
			correct_digest = hmac.new(_secret, msg=post_body, digestmod='sha1').hexdigest()

			# Do a secure comparison to make sure we have it
			if not hmac.compare_digest(correct_digest, check_digest):
				raise ForbiddenError()

		# Parse the payload as json
		try:
			request = json.loads(post_body)
		except json.JSONDecodeError:
			raise BadRequestError()

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
				top_message = '[{0}] {1} created {2} (+{3} new {4}): {5}'.format(
					repo_name,
					user,
					branch,
					size,
					'commit' if size == 1 else 'commits',
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
			top_message = '[{0}] {1} pushed {2} new {3} to {4}: {5}'.format(
				repo_name,
				user,
				size,
				'commit' if size == 1 else 'commits',
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


def _create_server(host, port, cert_file=None, hook=None, secret=None, ca_file=None, key_file=None):
	# Assign the hook
	global _message_hook
	_message_hook = hook

	# Assign the secret. Make sure it's encoded as a bytes object.
	global _secret
	if isinstance(secret, str):
		_secret = secret.encode('utf-8')
	else:
		_secret = secret

	# Create the basic server
	server = http.server.HTTPServer((host, port), GitHubRequestHandler)

	# Wrap in TLS if we have a cert
	if cert_file:
		# Create a client-authenticating context
		context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)

		# If there was a separate CA file, combine them into a single file with the
		# cert file.
		if ca_file:
			with tempfile.NamedTemporaryFile() as combined_fd:
				# Copy both files to a combined one
				for input_file_name in (cert_file, ca_file):
					with open(input_file_name, 'rb') as input_fd:
						shutil.copyfileobj(input_fd, combined_fd)

				# Ensure the file is flushed
				combined_fd.flush()

				# Load the cert chain using that
				context.load_cert_chain(combined_fd.name, key_file)
		else:
			# Load just the single file
			context.load_cert_chain(cert_file, key_file)

		# Wrap the socket
		server.socket = context.wrap_socket(server.socket, server_side=True)
	elif not ca_file or not key_file:
		# Misconfiguration
		raise Exception('Missing cert_file parameter')

	return server


def init_bot_webhook(host, port, bot, channels=[], **kwargs):
	# Create the server
	server = _create_server(host, port, hook=BotHook(bot, channels), **kwargs)

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
	parser.add_argument('--secret', help='The secret to check the hash against')
	parser.add_argument('--ca-file', help='Certificate authority file')
	parser.add_argument('--key-file', help='Private key file')
	args = parser.parse_args()

	# Create the server
	server = _create_server(args.host, args.port, hook=StdOutHook(), cert_file=args.cert_file, secret=args.secret, ca_file=args.ca_file, key_file=args.key_file)

	# Listen until someone sends in a SIGINT
	server.serve_forever()
