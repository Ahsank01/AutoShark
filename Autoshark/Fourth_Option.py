from Third_Option import runit
from Second_Option import extractfiles
from First_Option import get_all_ip

output = []

def save_to_list():
	x = get_all_ip()
	y = extractfiles()
  z = runit()
	output.append(x,y,z)

def write_to_file():
			with open('AutosharkOutput.txt', 'w') as f:
				for line in output:
					f.write(line)

def do_this:
	save_to_list()
	write_to_file()