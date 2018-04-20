"""
__author__ = Kyle McGlynn 11/12/2017
"""

import socket
import sys
import time
import math

def _traceroute( destination, n, q, s ):
	"""
	This function opens a raw socket, sends ICMP echo requests, modifies
	the ttl for every hop, and eventually either exceeds the maximum number
	of hops or arrives at the target destination.
	:param destination:   The destination, either an IPv4 address or web URL.
	:param n:             Print IPv4 addresses as numeric rather than numeric
	                      and symbolic.
	:param q:             The number of packets sent per ttl. Default value is 3.
	:param s:             Print a summary of how many packets were not answered
	                      for each hop.
	:return:              None
	"""
	
	# Open the socket
	send = socket.socket( socket.AF_INET, socket.SOCK_RAW, 1 )
	send.settimeout( 1 )
		
	# IPv4 address of destination
	try:
		destIPv4 = socket.gethostbyname( destination )
	except socket.gaierror:
		print( "Cannot handle \"host\" cmdline arg '" + destination + "' ")
		sys.exit(0)
	
	# First line of output
	print( "traceroute to " + destination + " (" + destIPv4 + "), " + 
	str( 30 ) + " hops max, " + str( 60 ) + " byte packets")
	
	# IPv4 address of the sender of the received packet
	senderIPv4 = ""
	
	# Keep track of the number of hops
	counter = 0
	
	# Current hop's rtt
	rtts = list()
	
	# Build packet
	packet = _icmp( 32, 1 )
	
	try:
		
		# Continue until we reach the destination OR max hops is reached.
		while( senderIPv4 != destIPv4 and counter < 30 ):
			
			# Reset to blank in case a server isn't set up to respond
			senderIPv4 = "" 
			source = ""
			
			# Set the ttl
			send.setsockopt( socket.SOL_IP, socket.IP_TTL, counter + 1)
					
			# Send and receive packets
			for i in range( 0, q ):
				
				# Start time for rtt calculation
				start = time.time()
				
				# Send the packet
				send.sendto( packet, ( destIPv4, 80 ) )
				
				# Get the packet
				try:
					arr = bytearray( 1000 )
					(nBytes, (senderIPv4, port) ) = send.recvfrom_into( arr )
					rtts.append( str( ( time.time() - start ) * 1000 ) )
				except socket.timeout:
					rtts.append( "*" )
						
			# Process results
			_processResults( counter + 1, senderIPv4, rtts, n, s )
			counter += 1
			rtts = list()
			
	except KeyboardInterrupt:
		sys.exit(0)

		
def _processResults( number, ipv4, rtts, n, s ):
	"""
	This function processes the packets returned for one hop. 
	It calculates the time and, is option s is true, the percentage
	of packet loss.
	:param number:   The numbered hop that was just tested
	:param ipv4:     The IPv4 address of the hop
	:param rtts:     An array of rtts times for each probe 
	:param n:        If true, the IPv4 of the hop is displayed 
	                 as numeric only, rather than numeric and symbolic
	:param s:        If true, the percentage of lost packets is displayed
	:return:         None
	"""	
	
	# If ipv4 is the empty string, than the 
	# machine for this hop did not respond to
	# the probes
	if( ipv4 == "" ):
		output = str(number) + "  "
	
	# If n is true, only print the numeric value
	elif n :
		output = str(number) + "  " + ipv4 + " "
	
	else:
		
		# Symbolic name of this IPv4 address
		source = ""
		try:
			(source, aliaslist, ipaddrlist) = socket.gethostbyaddr( ipv4 )
		except socket.herror:
			source = ipv4
		output = str(number) + "  "  + source + "  " + "(" + ipv4 + ")  "
	
	# Number of packets lost this round
	numberLost = 0
		
	# For every rtt value
	for i in rtts:
		
		# If '*', add it to output
		if( i == "*" ):
			output += i + " "
			numberLost += 1
			
		# Format the time	
		else:
			value = float( i )
			output += "{:4.3f}".format( value ) + " ms "
	
	# If the -S option was selected
	if s:
		percent = (numberLost / len(rtts)) * 100
		output += " (" + "{:.0f}".format( percent ) + "% loss)"
	print( output )
		
def _icmp( size, count ):
	"""
	This function assembles an ICMP echo request packet with the given
	amount of data and the given sequence number.
	:param size:    The amount of data sent in the echo request.
	:param count:   The sequence number of this particular echo request.
	:return:        A bytearray representation of this echo request packet.
	"""
	
	# The bytearray representing this echo request packet.
	icmpHeader = bytearray( 8 + size )
	
	# Echo type
	icmpHeader[0] = 8 
	
	# Code is zero
	icmpHeader[1] = 0
	
	# Checksum starts as zero
	icmpHeader[2] = 0
	icmpHeader[3] = 0
	
	# Identifier is zero
	icmpHeader[4] = 0
	icmpHeader[5] = 0
	
	# Sequence number is zero
	binary = _pad( bin(count)[2:], 16 )	
	icmpHeader[6] = int( binary[:8], 2 )
	icmpHeader[7] = int( binary[8:], 2 )
    
    # Send 56 bytes of ones as data
	total = size + 8
	for i in range(8, total):
		icmpHeader[i] = 1
	
	# Compute the 16-bit one's compliment of this packet.
	(icmpHeader[2], icmpHeader[3]) = _compute_checksum( icmpHeader )

	return icmpHeader
	
def _compute_checksum( header ):
	"""
	This function computes the sixteen bit one's compliment of the
	given bytearray.
	:param header:   A bytearray object for which we want to calculate
	                 the sixteen bit one's compliment.
	:return:         The bytes representing the sixteen bit checksum.
	"""
	
	# Take the sum
	total = _sixteenBitSum( header )
	
	# Convert to binary
	binary = bin( total )
    
    # Remove '0b'
	binarySub = binary[2:]
	
	length = len( binarySub )

	if length < 16:
		binarySub = '00' + binarySub

	else:
    
		
		while( len( binarySub ) != 16 ):
			
			# If this is zero, then we don't need to pad 
			rem = len( binarySub ) % 4
			for i in range( 0, rem ):
				binarySub = '0' + binarySub
		
			# Position of first sixteen bits
			begin = len( binarySub ) - 16 + 1
		
			# Get the carry and right hand side
			carry = int( binarySub[0:begin], 2 )
			right = int( binarySub[begin:], 2 )

			binarySub = bin( carry + right )[2:]
	
	# Flip every bit using XOR		
	binarySub = bin(int( binarySub, 2 ) ^ 65535)[2:]
	first = int( binarySub[0:8], 2)
	second = int( binarySub[8:], 2)

	return ( first, second )

def _sixteenBitSum( arr ):
	"""
	This function computes the sixteen bit sum of the given
	bytearray.
	:param arr:   The bytearray object for which we want
	              to calculate the sixteen bit sum.
	:return:      The sixteen bit sum.
	"""
	
	total = 0
	length = len( arr )
	for i in range( 0, length, 2 ):
		left = _pad( bin(arr[i])[2:], 8 )
		right = _pad( bin(arr[i+1])[2:], 8 )
		concat = left + right
		total += int( concat, 2 )
	return total

def _pad( string, length ):
	"""
	This function pads the left side of the given binary string 
	with zeros until the length of the string is equal to the
	length specified.
	:param string:   The binary string to pad.
	:param length:   The desired length of the padded string.
	:return:         The padded string.
	"""
	
	diff = length - len(string)
	for i in range(0,diff):
		string = '0' + string
	return string

def _parse( strArr ):
	"""
	This funciton parses the array of inputs to the ping program 
	for different possible options and the destination.
	:param strArr:   The array of inputs to the ping program.
	:return:         The specified settings for this particular
	                 execution of the ping program.
	"""
	
	# Starting location in the array of arguments
	pointer = 0
	
	# Print hop addresses as just numeric, not symbolic and numeric
	n = False
	
	# The number of probes (packets sent) per ttl
	q = 3
	
	# Print a summary of how many probes were not answered for each hop
	s = False
	
	# Destination of the ICMP echo request packets.
	addr = ""
	
	# Process options before address
	(addr, pointer, n, q, s) = _processOptions( 0, strArr, n, q, s )

	# Process options after address
	(bull, pointer, n, q, s) = _processOptions( pointer, strArr, n, q, s )	

	return (addr, n, q, s)
		
def _processOptions( index, strArr, n, q, s ):
	"""
	This function processes the array of ping program inputs for
	various options and their values. This function ends when
	the destination of the ICMP echo request packets is found or
	when there are no more inputes to process.
	:param index:    Index in the array that the processing will start at.
	:param strArr:   The array of inputs to the ping program.
	:param n:        Print IPv4 addresses as numeric rather than numeric
	                 and symbolic.
	:param q:        The number of packets sent per ttl. Default value is 3.
	:param s:        Print a summary of how many packets were not answered
	                 for each hop.
	:return: 		 Part of the specified settings for this particular
	                 execution of the ping program. 	  
	"""
	
	# Possible options
	valueLess = [ "-n", "-S" ]
	valued = [ "-q" ]
	
	# Number of arguments
	length = len( strArr )
	
	# Starting index in the array of arguments
	pointer = index
	
	# Continue until we find the destination
	flag = True
	while( flag ):
		try:
			
			# Check if we have reached the end
			if( pointer < length ):
				
				# If the current item is not a valueless option, 
				# it could be the destination or a valued option
				location = valueLess.index( strArr[pointer] )
				
				# Assess validity of value
				( n, q, s ) = _chooseOption( valueLess[location], True, n, q, s )
				pointer += 1
				
			else:
				flag = False
				
		# Thrown by options.index when we reach the destination		
		except ValueError:
			try:
				
				# If this doesn't fail, it is a valued option
				location = valued.index( strArr[pointer] )
				
				# Get the value associated with the option
				value = int(strArr[pointer+1])
				
				# Assess validity of value
				( n, q, s ) = _chooseOption( valued[location], value, n, q, s )
				pointer += 2
				
			except ValueError:
				flag = False
				addr = strArr[pointer]
				return ( addr, pointer + 1, n, q, s )
	return ( "", pointer, n, q, s  )	
	
def _chooseOption( option, value, n, q, s ):
	"""
	This function validates the value of a discovered option.
	:param option:   The option whose value we want to validate.
	:param value:    The value to be validated.
	:param n:        Print IPv4 addresses as numeric rather than numeric
	                 and symbolic.
	:param q:        The number of packets sent per ttl. Default value is 3.
	:param s:        Print a summary of how many packets were not answered
	                 for each hop.
	:return: 		 Part of the specified settings for this particular
	                 execution of the ping program. 
	"""
	
	if( option == "-n" ):
		return ( value, q, s )
			
	elif( option == "-q" ):
		try:
			q = int(value)
			if ( q <= 0 or q > 10 ): 
				sys.exit( "no more than 10 probes per hop")
			return ( n, value, s )
		except ValueError:
			sys.exit( "Cannot handle '-q' option with arg '" + str(value) + "'"  )
			
	else:
		return ( n, q, value)


def main():
	"""
	The main function. It first checks to make that the user has
	entered more than just the name of the program. If more has
	been entered, the input is processed. If the input is succesfully
	processed, then the traceroute program can start.
	"""
	
	if( len(sys.argv[1:]) == 0 ):
		print("Usage: traceroute [-q nqueries] [-n] [-S] destination")
	else:
		(destination, n, q, s ) = _parse( sys.argv[1:] )
		_traceroute( destination, n, q, s )
	
if __name__ == "__main__":
    main()

