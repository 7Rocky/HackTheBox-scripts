#!/usr/bin/env python3

from pwn import re, remote, sys


health_weight          = 0.2
agility_weight         = 0.3
charisma_weight        = 0.1
knowledge_weight       = 0.05
energy_weight          = 0.05
resourcefulness_weight = 0.3


class Candidate:
	def __init__(self,
				first_name: str,
				last_name: str,
				health: int,
				agility: int,
				charisma: int,
				knowledge: int,
				energy: int,
				resourcefulness: int):
		self.first_name = first_name
		self.last_name = last_name
		self.health = health
		self.agility = agility
		self.charisma = charisma
		self.knowledge = knowledge
		self.energy = energy
		self.resourcefulness = resourcefulness

	def overall(self) -> int:
		health_score = round(6 * self.health * health_weight) + 10
		agility_score = round(6 * self.agility * agility_weight) + 10
		charisma_score = round(6 * self.charisma * charisma_weight) + 10
		knowledge_score = round(6 * self.knowledge * knowledge_weight) + 10
		energy_score = round(6 * self.energy * energy_weight) + 10
		resourcefulness_score = round(6 * self.resourcefulness * resourcefulness_weight) + 10

		return round(5 * ((health_score * 0.18) + (agility_score * 0.20) + (charisma_score * 0.21) + (knowledge_score * 0.08) + (energy_score * 0.17) + (resourcefulness_score * 0.16)))


regex = r'^\s+(\w+?)\s+(\w+?)\s+(\d+?)\s+(\d+?)\s+(\d+?)\s+(\d+?)\s+(\d+?)\s+(\d+?)\s+$'
candidates = []

with open('data.txt') as f:
	while (line := f.readline()):
		matches = re.search(regex, line)

		if not matches:
			continue

		first_name = matches[1]
		last_name = matches[2]
		health = int(matches[3])
		agility = int(matches[4])
		charisma = int(matches[5])
		knowledge = int(matches[6])
		energy = int(matches[7])
		resourcefulness = int(matches[8])

		candidates.append(Candidate(
			first_name, last_name, health, agility, charisma, knowledge, energy, resourcefulness,
		))

candidates.sort(key=lambda c: c.overall(), reverse=True)

solution = ', '.join(
	f'{c.first_name} {c.last_name} - {c.overall()}' for c in candidates[:14]
)

host, port = sys.argv[1].split(':')
io = remote(host, port)
io.sendlineafter(b'> ', solution.encode())
io.success(io.recvline().decode())
