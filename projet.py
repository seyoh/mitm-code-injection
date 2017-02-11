#!/usr/bin/env python

import socket
import sys
from threading import Thread

HOTE="213.186.33.16"

def forward(data,sock):
	if len(data)>2000:
		print len(data)
	sock.send(data)


def request_default_behavior(data,client,serveur):
	data=data.replace("Host: 192.168.1.38","Host: www.la-ccr.fr") #a utiliser si on se connecte directement au proxy, remplacer l'ip par la sienne (mesure temporaire)
	###data = data.replace("Accept-Encoding: gzip, deflate","Accept-Encoding: ")
	return forward(data,serveur);

def response_default_behavior(data,client,serveur):
	return forward(data,client);

class Client_to_server(Thread):
# gere les connections client -> proxy et proxy -> serveur

	def __init__(self,client,serveur):
		Thread.__init__(self)
		self.client=client
		self.serveur=serveur

	def run(self):
		data="a"
		while len(data)>0:
			data = self.client.recv(2000)
			request_default_behavior(data,self.client,self.serveur)

		self.client.close()
		self.serveur.close()


class Server_to_client(Thread):
#gere les connections serveur -> proxy et proxy -> client

	def __init__(self,client,serveur):
		Thread.__init__(self)
		self.client=client
		self.serveur=serveur
	
	def run(self):
		data="a"
		while len(data)>0:
			data = self.serveur.recv(2000)
			response_default_behavior(data,self.client,self.serveur)
	
		self.client.close()
		self.serveur.close()


socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#socket_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
socket_server.bind(('', 80))
socket_server.listen(10)
while 1:
	visit,address = socket_server.accept()
	#creation de la socket proxy-> serveur
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #ici, client dans le sens socket, mais represente la connection proxy -> serveur
	client.connect((HOTE,80))

	#lancement d'un thread pour gerer la connection client-> proxy
	thread1 = Client_to_server(visit,client)
	thread1.start()

	#lancement d'un thread pour gerer la connection proxy -> serveur
	thread2 = Server_to_client(visit,client)
	thread2.start()

