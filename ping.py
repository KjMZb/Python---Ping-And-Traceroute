"""
__author__ = Kyle McGlynn 11/12/2017
"""

import socket
import sys
import time
import threading
import math

def _ping( destination, c, i, s, t ):
	"""
	This function opens a raw socket, sends ICMP echo requests to the
	destination, receives ICMP echo responses, and passes the statistics
	to the _statistics function.
	:param destination:   The destination, either an IPv4 address or web URL.
	:param c:             The number of packets to be sent. If zero, it is
	                      the 'default' value and is interpreted as infinity.
	:param i:             The number of seconds before another packet is sent.
	:param s:             The size of the data to be sent in each ICMP echo request.
	:param t:             The number of seconds before the program exits. If zero,
	                      it is the 'default' value and is interpreted as infinity.
	:return:              None
	"""

    # Open the raw socket
	send = socket.socket( socket.AF_INET, socket.SOCK_RAW, 1 )
	
	# Set to zero seconds to prevent blocking
	send.settimeout(0)
	
	# Get destination IP address
	try:
		destIPv4 = socket.gethostbyname( destination )
	except socket.gaierror:		
		print( "ping: unknown host " + destination )
		sys.exit(0)
	
	# Used to communicate between the timeout thread adn the main thread
	flagLock = threading.Lock()
	flag = [True]
	
	# The timeout thread. Once t seconds have ellapsed, the program terminates
	threading.Thread( target=_checkTime, args=(t, flagLock, flag, ) ).start()
	
	# The rtt of each received ICMP echo response
	stats = list()
	
	# Number of sent packets
	counter = 0
	
	print("PING " + destination + " (" + destIPv4 + ") " +
	 str(s) + "(" + str(s+28) + ") bytes of data." )
	
	# Record start time of packet send/receive
	enter = time.time()
	 
	# If the user hits Ctrl+C, stop sending packets 
	try:
		
		# Send packets so long as a timeout has not occured or a specified 
		# number of packets has not been sent
		while( _checkFlag( flagLock, flag ) and _checkCount( c, counter ) ):
			
			# Build the packet
			packet = _icmp( s, counter + 1 )
			counter += 1
			
			# Send the packet
			send.sendto( packet, (str(destIPv4), 80) )
			
			# Get the response packet
			start = time.time()
			
			# So long as the waiting period has not
			# passed, continue
			while( time.time() - start < i ):
				
				# If a timeout has occured, cancel
				if( _checkFlag( flagLock, flag) is False ):
					start = i
				try:
					arr = bytearray(100)
					(nbytes, (senderIPv4, port)) = send.recvfrom_into( arr )
					rtt = ( time.time() - start ) * 1000
					_processPackets( senderIPv4, arr, rtt )
					stats.append( rtt )
				except BlockingIOError:
					bull = ""	
			
	except KeyboardInterrupt:
		bull=""
		
	# Compute total time spent	
	ellapsed = ( time.time() - enter ) * 1000
	
	# Compute and display statistics
	_statistics( counter, stats, destination, ellapsed )
	sys.exit(0)

def _processPackets( sender, packet, rtt ):
	"""
	This function processes the received packet, extracting the 
	packet size, ttl, ICMP sequence, and computing the alternative
	name of the destination.
	:param sender:   The sender of the ICMP echo response.
	:param packet:   The received packet.
	:param rtt:      The round trip time between ICMP echo request and 
	                 echo response.
	:return:         None.
	"""
	
	# Size
	lengthL = packet[2]
	lengthR = packet[3]
	length = int( ( bin( lengthL )[2:] + bin( lengthR )[2:] ) ,2 )
	size = length - 20 # Minus 20 bytes for size of IP header
	
	# TTL
	ttl = packet[8]
	
	# ICMP Seq
	icmp_seqL = packet[26]
	icmp_seqR = packet[27]
	icmp_seq = int( ( bin( icmp_seqL )[2:] + bin( icmp_seqR )[2:] ), 2 )
	
	# Alternative name
	(source, aliaslist, ipaddrlist) = socket.gethostbyaddr( sender )
	
	print( str(size) + " bytes from " + str(source) + " (" + sender +
	 "): icmp_seq=" + str(icmp_seq) + " ttl=" + str(ttl) + " time=" +
	 "{:4.1f}".format(rtt) + " ms")
	
def _statistics( sent, stats, destination, ellapsed ):
	"""
	This function calculates the statistics of this ping operation, such
	as: minimum rtt, max rtt, average rtt, and standard deviation.
	:param sent:          The number sent ICMP echo request packets
	:param stats:         The rtt of the received ICMP echo reponse packets
	:param destination:   The destination of the ICMP echo request packets
	:param ellapsed:      The amount of time spent sending and receiving packets
	:return:              None
	"""
	
	# Stats title
	print("")
	print( "--- " + destination + " ping statistics --" )

	# Number received
	received = len( stats )
	
	# Percent lost
	lost = 100 - ( ( received / sent ) * 100 )
	
	# Second line of stats
	print( str(sent) + " packets transmitted, " + str(received) + " received, " +
	"{:4.1f}".format(lost) + "% packet loss, time " + "{:4.0f}".format(ellapsed) + "ms" ) 
	
	# If none were received, don't calculate statistics
	if( received > 0 ):
			
		#Total time
		total = sum( stats )
		
		# Min
		minimum = min( stats )
		
		# Max 
		maximum = max( stats )
		
		# Avg
		average = total / received
		
		# StdDev
		standard_dev = _standardDev( stats, average )
		
		# Last line of stats
		print( "rtt min/avg/max/mdev = " + "{:6.3f}".format(minimum) + "/" +
		"{:6.3f}".format(average) + "/" + "{:6.3f}".format(maximum) + "/" + 
		"{:5.3f}".format(standard_dev) + "ms")
	
	else:
		print()
	
def _standardDev( stats, average ):
	"""
	This function calculates the standard deviation between
	the rtts of the different packets.
	:param stats:     A collection of values for which we want
	                  to discover the standard deviation.
	:param average:   The average value of collection.
	:return:          The standard deviation of the collection.
	"""
	total = 0
	for i in stats:
		total += pow( ( average - i ), 2)
	return math.sqrt( total )	
	
def _checkCount( c, count ):
	"""
	This function checks to make sure that the specified number of packets
	has not yet been sent yet.
	:param c:       The maximum number that will be sent.
	                If this value is zero, it is interpreted as infinity.
	:param count:   The number of packets sent so far.
	:return:        True if there are more packets to be sent. False
	                otherwise.
	"""
	
	# If c=0, then count is not part of ping's exit condition.
	# If c/=0, then count is part of ping's exit condition.
	if( c == 0 or count is not c ):
		return True
	else:
		return False

def _checkTime( t, lock, flag ):
	"""
	This function checks to make sure that the specified number
	of seconds have not yet ellapsed.
	:param t:      The total number of seconds before the program terminates.
	:param lock:   A lock to prevent simultaneous access.
	:param flag:   A shared value between the thread using this
	               function and the main thread.
	:return:       None
	"""
	
	if( t > 0 ):
		time.sleep(t)
		lock.acquire()
		flag[0] = False
		lock.release()

def _checkFlag( lock, flag ):
	"""
	This function checks to see if the boolean value shared between
	the timeout and main threads has been altered.
	:param lock:   A lock to prevent simultaneous access.
	:param flag:   A shared value between the thread using this
	               function and the timeout thread.
	:return:       None	               
	"""
	
	lock.acquire()
	boolean = flag[0]
	lock.release()	
	return boolean
		
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
	
	# Number of packets to send. This default value of zero is 
	# interpreted as infinity.
	c = 0
	
	# The number of seconds between sent ICMP echo request packets.
	# One is the default value.
	i = 1
	
	# The number of bytes of data to be sent in the ICMP echo
	# request packet. The default value is 56 bytes.
	s = 56
	
	# The numebr of seconds the ping program should run for.
	# This default value of zero is interpreted as infinity.
	t = 0
	
	# Destination of the ICMP echo request packets.
	addr = ""
	
	# Process options before address
	(addr, pointer, c, i, s, t) = _processOptions( 0, strArr, c, i, s, t )

	# Process options after address
	(bull, pointer, c, i, s, t) = _processOptions( pointer, strArr, c, i, s, t )	

	return (addr, c, i, s, t)
		
def _processOptions( index, strArr, c, i, s, t ):
	"""
	This function processes the array of ping program inputs for
	various options and their values. This function ends when
	the destination of the ICMP echo request packets is found or
	when there are no more inputes to process.
	:param index:    Index in the array that the processing will start at.
	:param strArr:   The array of inputs to the ping program.
	:param c:        The number of packets to be sent. If zero, it is
	                 the 'default' value and is interpreted as infinity.
	:param i:        The number of seconds before another packet is sent.
	:param s:        The size of the data to be sent in each ICMP echo request.
	:param t:        The number of seconds before the program exits. If zero,
	                 it is the 'default' value and is interpreted as infinity.
	:return: 		 Part of the specified settings for this particular
	                 execution of the ping program. 	  
	"""
	
	# Possible options
	options = [ "-c", "-i", "-s", "-t" ]
	
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
				
				# If the current item is not an option, it must be the destination
				location = options.index( strArr[pointer] )
				
				# Get the value associated with the option
				value = float(strArr[pointer+1])
				
				# Assess validity of value
				( c, i, s, t ) = _chooseOption( options[location], value, c, i, s, t )
				pointer += 2
				
			else:
				flag = False
				
		# Thrown by options.index when we reach the destination		
		except ValueError:
			flag = False
			addr = strArr[pointer]
			return ( addr, pointer + 1, c, i, s, t )
	return ( "", pointer, c, i, s, t )	
	
def _chooseOption( option, value, c, i, s, t ):
	"""
	This function validates the value of a discovered option.
	:param option:   The option whose value we want to validate.
	:param value:    The value to be validated.
	:param c:        The number of packets to be sent. If zero, it is
	                 the 'default' value and is interpreted as infinity.
	:param i:        The number of seconds before another packet is sent.
	:param s:        The size of the data to be sent in each ICMP echo request.
	:param t:        The number of seconds before the program exits. If zero,
	                 it is the 'default' value and is interpreted as infinity.
	:return: 		 Part of the specified settings for this particular
	                 execution of the ping program. 
	"""
	
	if( option == "-c" ):
		try:
			c = int(value)
			if c <= 0:
				sys.exit( "ping: bad number of packets to transmit." )
			return ( c, i, s, t )
		except ValueError:
			sys.exit( "ping: bad number of packets to transmit." )
			
	elif( option == "-i" ):
		try:
			i = float(value)
			if i <= 0: 
				sys.exit( "ping: cannot flood; minimal interval allowed for user is 200ms")
			return ( c, i, s, t )
		except ValueError:
			sys.exit( "ping: bad timing interval" )
			
	elif( option == "-s" ):
		try:
			s = int(value)
			if s < 0:
				sys.exit( "ping: illegal negative packet size " + str(s) + "." )
			return ( c, i, s, t )
		except:
			sys.exit( "ping: bad packet size" )
	else:
		try:
			t = float(value)
			if t < 0:
				sys.exit( "ping: bad wait time." )
			return ( c, i, s, value )
		except:
			sys.exit( "ping: bad timeout" )
			
def main():
	"""
	The main function. It first checks to make that the user has
	entered more than just the name of the program. If more has
	been entered, the input is processed. If the input is succesfully
	processed, then the ping program can start.
	"""
	
	if( len(sys.argv[1:]) == 0 ):
		print("Usage: ping [-c count] [-i wait] [-s packetsize] [-t timeout] destination")
	else:
		(addr, c, i, s, t) = _parse(sys.argv[1:])
		if( addr[0] == "-"):
			print("Usage: ping [-c count] [-i wait] [-s packetsize] [-t timeout] destination")
		else:	
			_ping(addr, c, i, s, t)
	
if __name__ == "__main__":
    main()
