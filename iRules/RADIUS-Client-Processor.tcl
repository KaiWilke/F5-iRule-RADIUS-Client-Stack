when RULE_INIT {

	#======================================================================
	#######################################################################
	#+ Configuration of TCL script pre-compiler
	#

	set RadCLI_compiler(enable)				1				;# Enable TCL Script compiling (0-1 Bolean)

	set RadCLI_compiler(enable_input_validation)		1				;# Perform initial input validation (0-1 Bolean)
	set RadCLI_compiler(enable_variable_cleanup)		1				;# Enable flushing of request (after processing) and response (before processing) variables to support consecutive executions
	set RadCLI_compiler(request_tracing_enable)		1				;# Enable session_state() export/import tracing (0-1 Bolean)
	set RadCLI_compiler(istats_enable)			1				;# Enable istats performance counters (0-1 Bolean)
	set RadCLI_compiler(compression_enable) 		1				;# Enable TCL variable compression (0-1 Bolean)
	set RadCLI_compiler(remove_unnecessary_lines)		1				;# Enable to remove empty and unnecessary lines of code

	set RadCLI_compiler(log_enable)				1				;# Enable logging (0-1 Bolean)
	set RadCLI_compiler(log_prefix)				"RadCLI : \[virtual\] : "	;# Configure a common log-prefix. Escape TCL commands/variables to allow a execution/substitution during run-time.
	set RadCLI_compiler(log_level)				6				;# Include the log-lines up to log-level (0-8 See description below)
												;#
												;#	0	Emergency	Not used by this iRule
												;#	1	Alert		Not used by this iRule
												;# 	2	Critical	Not used by this iRule
												;#	3	Error		Not used by this iRule
												;#	4	Warning		Configuration Issues
												;#	5	Notice		Accounting Information (Accept/Reject)
												;#	6	Informational	Requests, responses and connection errors
												;#	7	Debug		Only important debug messages
												;#	8	Trace		Line-by-Line debug messages

	#
	# Configuration of TCL script pre-compiler
	#######################################################################
	#======================================================================

set static::RadCLI_Processor {

	#======================================================================
	#######################################################################
	#+ Handler for RADIUS client execution
	#

	#######################################################################
	#+ Handler for unique RADIUS request ID generation
	#

	# Note: The variable RadPOL(request_timestamp) could be set within RADIUS Policy scripts to support unique logging information.

	if { [info exists RadPOL(request_timestamp)] } then {

		set RadCLI(request_timestamp) $RadPOL(request_timestamp)

		#log7 "The request timestamp was successfully passed from RADIUS Policy script."

	} else {

		set RadCLI(request_timestamp) "[TMM::cmp_unit][clock clicks]"

		#log7 "A fresh request timestamp was successfully generated."

	}

	#
	# Handler for unique RADIUS request ID generation
	#######################################################################

	#cleanup #######################################################################
	#cleanup #+ Handler for variable clearance
	#cleanup #

	#cleanup #log8 "Clearing any server_response() variables which may have been created from previous executions." 

	#cleanup unset -nocomplain server_response

	#cleanup #
	#cleanup # Handler for variable clearance
	#cleanup #######################################################################

	#######################################################################
	#+ Handler for outer [while] wrapper
	#

	#log8 "Initializing an outer \[while\] wrapper to support break points without ending the entire script."

	while { 1 } {

		#input #######################################################################
		#input #+ Per-Request Configration validation
		#input #

		#input #log8 "Checking if the provided RADIUS request configuration variables are set and valid."

		#input if { ( ( [info exists server_config(address)] == 0 )
		#input     or ( $server_config(address) eq "" ) )
		#input   or ( ( [info exists server_config(shared_key)] == 0 )
		#input     or ( $server_config(shared_key) eq "" ) )
		#input   or ( ( [info exists server_config(timeout)] == 0 )
		#input     or ( $server_config(timeout) eq "" ) )				
		#input   or ( [info exists server_config(retransmits)] == 0 ) } then {

			#input #######################################################################
			#input #+ Handler to exit the TCL script
			#input #

			#input #log4 "Configuration error: The provided RADIUS server configuration is invalid."

			#input set server_response(code) 0
			#input set server_response(message) "Configuration error: The provided RADIUS server configuration is invalid."

			#input #log8 "Exiting the outer \[while\] wrapper."

			#input break

			#input #
			#input # Handler to exit the TCL script
			#input #######################################################################

		#input } elseif { ( ( [info exists client_request(username)] == 0 )
		#input           or ( $client_request(username) eq "" ) )				
		#input         or ( ( [info exists client_request(password)] == 0 )
		#input           or ( $client_request(password) eq "" ) ) } then {

			#input #######################################################################
			#input #+ Handler to exit the TCL script
			#input #

			#input #log4 "Configuration error: The provided RADIUS request username and/or password is invalid. It must not have an empty value."

			#input set server_response(code) 0
			#input set server_response(message) "Configuration error: The provided RADIUS request username and/or password is invalid."

			#input #log8 "Exiting the outer \[while\] wrapper."

			#input break

			#input #
			#input # Handler to exit the TCL script
			#input #######################################################################

		#input } elseif { ( [info exists client_request(attributes)] )
		#input        and ( [llength $client_request(attributes)] % 3 != 0 ) } then {

			#input #######################################################################
			#input #+ Handler to exit the TCL script
			#input #


			#input #log4 "Configuration error: The provided RADIUS request attributes are invalid. It must be a consecutive list of Attribute-ID, Attribute-Value-Format and Attribute-Value pairs."

			#input set server_response(code) 0
			#input set server_response(message) "Configuration error: The provided RADIUS request attributes are invalid"

			#input #log8 "Exiting the outer \[while\] wrapper."

			#input break

			#input #
			#input # Handler to exit the TCL script
			#input #######################################################################

		#input }

		#input #log7 "The provided RADIUS request configuration variables are set and valid."

		#input #
		#input # Per-Request Configration validation
		#input #######################################################################

		#log6 "Starting to process the RADIUS client request for username \"$client_request(username)\" to server \"$server_config(address)\""

		#istats #######################################################################
		#istats #+ Handler for unique RADIUS request ID generation
		#istats #

		#istats #log8 "Checking if a istats label was set within RADIUS Proxy Policy scripts to differentiate statistics of indipendent RADIUS client configurations."

		#istats if { [info exists server_config(istats_label)] } then {

		#istats 	# 
		#istats 	set RadCLI(istats_label) "_$server_config(istats_label)"
		#istats } else {
		#istats 	set RadCLI(istats_label) "" 
		#istats }

		#istats #
		#istats # Handler for unique RADIUS request ID generation
		#istats #######################################################################

		#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Executions" 1

		#######################################################################
		#+ Handler for RADIUS request ID and request authenticator generation
		#

		#log8 "Setting the RADIUS request ID always to \"1\" (aka. we use a singleplex connection handling)."

		set RadCLI(request_id) 1

		#log8 "Calculating a random RADIUS request authenticator based on a MD5 of \"RADIUS ShareKey+TMM Core+Epoch Time\"."

		set RadCLI(request_authenticator) [md5 "$server_config(shared_key)[TMM::cmp_unit][clock clicks]"]

		#
		# Handler for RADIUS request ID and request authenticator generation
		#######################################################################

		#######################################################################
		#+ Handler for RADIUS password attribute encryption
		#

		#log8 "Encrypting the provided RADIUS request password value."
		#log8 "Checking if the provided password value completely fills one or many 16-byte / 128-bit cipher block(s)."

		if { [string length $client_request(password)] % 16 > 0 } then {

			#log7  "The password value does not fill one or many 16-byte / 128-bit cipher block(s)."
			#log8 "Zero-Padding the password value to a multiple of 16-byte / 128-bit to completely fill one or many 16-byte / 128-bit cipher block(s)."

			set client_request(password) [binary format a[expr { ( int( [string length $client_request(password)] / 16 ) + 1 ) * 16 }] $client_request(password)]

		}

		#log8 "Checking if the provided password value is stored in one or many 16-byte / 128-bit cipher block(s)."

		if { [string length $client_request(password)] == 16 } then {

			#log7 "The password can be stored in a single 16-byte / 128-bit cipher block. Using an optimized function to encrypt the contained password value."
			#log8 "Chunking and converting the plaintext password value into two subsequent 64-bit integer values."

			binary scan $client_request(password) WW\
								RadCLI(plaintext_password_64bit_chunk_1)\
								RadCLI(plaintext_password_64bit_chunk_2)

			#log8 "Calculating the 128-bit encryption key using the RADIUS-Shared-Secret and the randomly generated RADIUS request authenticator value."
			#log8 "Chunking and converting the generated 128-bit encryption key into two 64-bit integer values."

			binary scan [md5 "$server_config(shared_key)$RadCLI(request_authenticator)"] WW\
													RadCLI(encryption_key_64bit_chunk_1)\
													RadCLI(encryption_key_64bit_chunk_2)

			#log8 "Performing XOR operation with the corresponding plaintext block / encryption key 64-bit integer values."
			#log8 "Converting the encrypted 64-bit integer password values to their binary representation."

			set RadCLI(encrypted_password) [binary format WW\
									[expr { $RadCLI(plaintext_password_64bit_chunk_1) ^ $RadCLI(encryption_key_64bit_chunk_1) }]\
									[expr { $RadCLI(plaintext_password_64bit_chunk_2) ^ $RadCLI(encryption_key_64bit_chunk_2) }]\
							]

		} else {

			#log7 "The password must be stored in more than one 16-byte / 128-bit cipher block(s). Using the generic function to encrypt the contained password value."
			#log8 "Chunking and converting the password value into a list of subsequent 64-bit integer values."

			binary scan $client_request(password) W* RadCLI(plaintext_password_64bit_chunks)

			#log8 "Set the initial key seed to the randomly generated RADIUS request authenticator value."

			set RadCLI(encryption_iv) $RadCLI(request_authenticator)

			#log8 "Looping pair-wise through the list of password chunks to encrypt a full cipher block at once and then rotate the key for the next block."

			foreach { RadCLI(plaintext_password_64bit_chunk_1) RadCLI(plaintext_password_64bit_chunk_2) } $RadCLI(plaintext_password_64bit_chunks) {

				#log7 "Calculating the 128-bit encryption key using the RADIUS-Shared-Secret and current key seed as input."
				#log8 "Chunking and converting the generated 128-bit encryption key into two 64-bit integer values."

				binary scan [md5 "$server_config(shared_key)$RadCLI(encryption_iv)"] WW\
													RadCLI(encryption_key_64bit_chunk_1)\
													RadCLI(encryption_key_64bit_chunk_2)

				#log8 "Performing XOR operation with the corresponding cipher block / encryption key 64-bit integers."
				#log8 "Appending the encrypted 64-bit integers password values to the list of already encrypted values."

				lappend RadCLI(encrypted_password_64bit_chunks) [expr { $RadCLI(plaintext_password_64bit_chunk_1) ^ $RadCLI(encryption_key_64bit_chunk_1) }]\
										[expr { $RadCLI(plaintext_password_64bit_chunk_2) ^ $RadCLI(encryption_key_64bit_chunk_2) }]

				#log8 "Setting the encryption key seed for the next cipher block to the encrypted value of the current cipher block."

				set RadCLI(encryption_iv) [binary format W* [lrange $RadCLI(encrypted_password_64bit_chunks) end-1 end]]

			}

			#log8 "Converting the list of encrypted 64-bit integer password values to their binary representation."

			set RadCLI(encrypted_password) [binary format W* $RadCLI(encrypted_password_64bit_chunks)]

		}

		#log7 "Successfully decrypted the provided RADIUS request password value."

		#
		# Handler for RADIUS password attribute encryption
		#######################################################################

		#######################################################################
		#+ Handler for RADIUS request attribute definition
		#

		#log8 "Initializing the RADIUS request attributes."
		#log7 "Setting the RADIUS request username attribute (1) to \"$client_request(username)\"."

		lappend client_request(attributes) 1  string $client_request(username)

		#log7 "Setting the RADIUS request password attribute (2) to the encrypted password value."

		lappend client_request(attributes) 2  binary $RadCLI(encrypted_password)

		#log7 "Setting the RADIUS request NAS-IPv4 attribute (4) to the IPv4 of the requesting Virtual Server \"[getfield [IP::local_addr] "%" 1]\"."

		lappend client_request(attributes) 4  ipv4  [getfield [IP::local_addr] "%" 1]

		#log7 "Setting the RADIUS request Service-Type attribute (6) to \"Authenticate Only (8)\"."

		lappend client_request(attributes) 6  int32  8

		#log7 "Setting the RADIUS request Calling-Station-ID attribute (31) to the IPv4 of the connecting Client \"[getfield [IP::client_addr] "%" 1]\"."

		lappend client_request(attributes) 31 string [getfield [IP::client_addr] "%" 1]

		#log7 "Setting the RADIUS request NAS-ID attribute (32) to the name of the requesting Virtual Server \"[URI::basename [virtual]]\"."

		lappend client_request(attributes) 32 string [URI::basename [virtual]]

		#
		# Handler for RADIUS default attribute contruction
		#######################################################################

		#request #######################################################################
		#request #+ Handler for RADIUS request logging
		#request #

		#requestlog "[string repeat "\u0023" 30] RADIUS Request [string repeat "\u0023" 31]"
		#requestlog "Username    =  $client_request(username)"
		#request foreach { RadCLI(request_attribute_type) RadCLI(request_attribute_format) RadCLI(request_attribute_value) } $client_request(attributes) {
			#requestlog "AttributeID $RadCLI(request_attribute_type) = $RadCLI(request_attribute_format)([URI::encode $RadCLI(request_attribute_value)])"
		#request }
		#requestlog "[string repeat "\u0023" 30] RADIUS Request [string repeat "\u0023" 31]"

		#request #
		#request # Handler for RADIUS request logging
		#request #######################################################################

		#######################################################################
		#+ Handler for RADIUS request attribute construction
		#
		# 0               1               2               3               4 byte
		# 0                   1                   2                   3
		# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 bits
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |  Attr1-Code   |  Attr1-Length |         Attr1-Value           |
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |  Attr1-Value (cont) ...       |  AttrN-Code   |  AttrN-Length |
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |  					   AttrN-Value (cont) ...                 |
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |  AttrN-Value (cont) ...


		#log8 "Skipping through the list of RADIUS response attributes to construct the RADIUS attribute field."

		foreach { RadCLI(request_attribute_type) RadCLI(request_attribute_format) RadCLI(request_attribute_value) } $client_request(attributes) {

			#log8 "Processing an attribute with code \"$RadCLI(request_attribute_type)\". Checking if RADIUS response attribute has an empty value."

			if { $RadCLI(request_attribute_value) eq "" } then {

				#log8 "The attribute value is empty. Omitting the addition of empty value attribute."

				continue

			}

			#log8 "The attribute to be insert has a value set. Checking the data type of the attribute and apply proper formating..."

			switch -exact -- $RadCLI(request_attribute_format) {

				"int16" {

					#log8 "Convert the attibute value from int16() to its binary representation."

					set RadCLI(request_attribute_value) [binary format S* $RadCLI(request_attribute_value)]

				}
				"int32" {

					#log8 "Convert the attibute value from int32() to its binary representation."

					set RadCLI(request_attribute_value) [binary format I* $RadCLI(request_attribute_value)]

				}
				"int64" {

					#log8 "Convert the attibute value from int64() to its binary representation."

					set RadCLI(request_attribute_value) [binary format W* $RadCLI(request_attribute_value)]

				}
				"hex" {

					#log8 "Convert the attibute value from hex() to its binary representation."

					set RadCLI(request_attribute_value) [binary format H* $RadCLI(request_attribute_value)]

				}
				"b64" {

					#log8 "Convert the attibute value from base64() to its binary representation."

					set RadCLI(request_attribute_value) [b64decode $RadCLI(request_attribute_value)]

				}
				"ipv4" {

					#log8 "Convert the attibute value from IPv4 notation to its binary representation."

					set RadCLI(request_attribute_value) [binary format c4 [split $RadCLI(request_attribute_value) "."]]

				}
				"ipv4prefix" {

					#log8 "Convert the attibute value from IPv4-CIDR notation to its binary representation."

					set RadCLI(request_attribute_value) [binary format ccc4\
												0\
												[findstr $RadCLI(request_attribute_value) "/" 1]\
												[split [substr $RadCLI(request_attribute_value) 0 "/"] "."]\
									    ]

				}
				default {

					#log8 "The attibute value is already an octed stream and does not require converting."

				}

			}

			#log8 "Constructing the RADIUS response attribute and adding it to the list of existing response attributes."

			append RadCLI(request_attributes_field) [binary format cca*\
										$RadCLI(request_attribute_type)\
										[expr { 2 + [string length $RadCLI(request_attribute_value)] }]\
										$RadCLI(request_attribute_value)\
								]


			#log8 "Checking if another attribute needs to be insert..."

		}

		#log7 "Finished construction of the RADIUS request attribute field."

		#
		# Handler for RADIUS request attribute construction
		#######################################################################

		#######################################################################
		#+ Handler for RADIUS request contruction
		#
		# 0               1               2               3               4 byte
		# 0                   1                   2                   3
		# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 bits
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
		# |      Code     |  Identifier   |            Length             |
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |                                                               |
		# |                         Authenticator                         |
		# |                           (16 bytes)                          |
		# |                                                               |
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |  				Default-Attributes  (X bytes)                 |
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |    Code 80    |   Length 18  |      HMAC-MD5 Checksum...      |
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |  ... HMAC-MD5 Checksum ... (16 bytes)


		#log8 "Calculating the length of the RADIUS request payload by combining the length of request headers (20-bytes), request attributes (n-bytes) and the RADIUS Message Authenticator attribute (18-bytes)."

		set RadCLI(request_length) [expr { 20 + [string length $RadCLI(request_attributes_field)] + 18 }]

		#log8 "Contructing the RADIUS Access-Request payload by including the RADIUS request code, -identifier, -length, -authenticator, -attributes fields and a HMAC-MD5 based message authenticator."

		set RadCLI(request_payload) [binary format ccSa*a*cca*\
									1\
									$RadCLI(request_id)\
									$RadCLI(request_length)\
									$RadCLI(request_authenticator)\
									$RadCLI(request_attributes_field)\
									80\
									18\
									[CRYPTO::sign -alg hmac-md5 -key $server_config(shared_key)\
										[binary format ccSa*a*cca*\
													1\
													$RadCLI(request_id)\
													$RadCLI(request_length)\
													$RadCLI(request_authenticator)\
													$RadCLI(request_attributes_field)\
													80\
													18\
													"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
										]\
									]\
					    ]

		#log7 "Finished construction of the RADIUS Access-Request payload."

		#
		# Handler for RADIUS request contruction
		#######################################################################

		#######################################################################
		#+ Handler for Sideband connection establishment processing
		#

		#log8 "Trying to establishing the Sideband connection to the RADIUS server \"$server_config(address)\"."

		if { [catch {

			set RadCLI(sideband_connection) [connect\
								-status RadCLI(sideband_connection_status)\
								-protocol udp\
								-timeout 500\
								-idle [expr { round( ( $server_config(timeout) * 2 ) / 1000.0 ) }]\
								$server_config(address)\
							]

		}] } then {

			#######################################################################
			#+ Handler to exit the TCL script
			#

			#log4 "Configuration error: The Sideband connection attempt to \"$server_config(address)\" generated a TCL stack trace. Reason: [getfield [subst \$::errorInfo] " (line" 1]."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Sideband_Connection_Failiures" 1

			set server_response(code) 0
			set server_response(message) "The Sideband connection to \"$server_config(address)\" generated a TCL stack trace. Reason: [getfield [subst \$::errorInfo] " (line" 1]"

			#log8 "Exiting the outer \[while\] wrapper."

			break

			#
			# Handler to exit the TCL script
			#######################################################################

		}

		#log8 "Checking the Sideband connection status."

		if { $RadCLI(sideband_connection_status) ne "connected" } then {

			#######################################################################
			#+ Handler to exit the TCL script
			#

			#log6 "The Sideband connection to \"$server_config(address)\" could not be established. The received error code is \"$RadCLI(sideband_connection_status)\"."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Sideband_Connection_Failiures" 1

			set server_response(code) 0
			set server_response(message) "The Sideband connection to \"$server_config(address)\" could not be established. Reason: \$RadCLI(sideband_connection_status)"

			#log8 "Actively closing the Sideband connection."

			close $RadCLI(sideband_connection)

			#log8 "Exiting the outer \[while\] wrapper."

			break

			#
			# Handler to exit the TCL script
			#######################################################################

		}

		#log6 "The Sideband connection to \"$server_config(address)\" has been established sucessfully."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Sideband_Connection_Success" 1

		#
		# Handler for Sideband connection establishment processing
		#######################################################################

		#######################################################################
		#+ Handler for Sideband initial RADIUS request processing
		#

		#log6 "Sending the initial RADIUS Access-Request to RADIUS server."

		catch { 

			send\
				-status RadCLI(sideband_connection_status)\
				$RadCLI(sideband_connection)\
				$RadCLI(request_payload)

		}

		#log8 "Checking if the RADIUS request could be sent successfully."

		if { $RadCLI(sideband_connection_status) ne "sent" } then {

			#######################################################################
			#+ Handler to exit the TCL script
			#

			#log6 "The RADIUS Access-Request could not be sent the request to RADIUS server. The received error code is \"$RadCLI(sideband_connection_status)\"."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Sideband_Send_Failiures" 1

			set server_response(code) 0
			set server_response(message) "The Sideband connection could not sent the request to RADIUS server. Reason: $RadCLI(sideband_connection_status)"

			#log8 "Actively closing the Sideband connection."

			close $RadCLI(sideband_connection)

			#log8 "Exiting the outer \[while\] wrapper."

			break

			#
			# Handler to exit the TCL script
			#######################################################################

		}

		#log7 "The initial RADIUS Access-Request was sent sucessfully."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Sideband_Send_Success" 1

		#
		# Handler for Sideband initial RADIUS request processing
		#######################################################################

		#######################################################################
		#+ Handler for Sideband RADIUS response and retransmit processing
		#

		#log8 "Storing the current Epoch-Time to support the Sideband retransmission timers and statistics."

		set RadCLI(sideband_connection_timestamp) [clock clicks -milliseconds]

		#log8 "Checking if Sideband retransmission timers are configured."

		if { $server_config(retransmits) eq "" } then {

			#######################################################################
			#+ Handler for Sideband RADIUS response and selective retransmit processing
			#

			#log8 "Sideband retransmission timers are not configured. Waiting a maximum of the configured Sideband timeout value for arrival of the RADIUS response."

			recv \
				-timeout $server_config(timeout)\
				-status RadCLI(sideband_connection_status)\
				-peek\
				1\
				$RadCLI(sideband_connection)\
				RadCLI(response_payload)

			#
			# Handler for Sideband RADIUS response processing without retransmits
			#######################################################################

		} else {

			#######################################################################
			#+ Handler for Sideband RADIUS response processing with retransmits
			#

			#log8 "Sideband retransmission timers are configured. Skipping through the list of configured Sideband retransmit intervals."

			foreach { RadCLI(sideband_retransmit) } $server_config(retransmits) {

				#log8 "Waiting a maximum of the currently processed Sideband retransmit interval ($RadCLI(sideband_retransmit) ms) for arrival of the RADIUS response."

				recv \
					-timeout [expr { $RadCLI(sideband_retransmit) - ( [clock clicks -milliseconds] - $RadCLI(sideband_connection_timestamp) ) }]\
					-status RadCLI(sideband_connection_status)\
					-peek\
					1\
					$RadCLI(sideband_connection)\
					RadCLI(response_payload)

				#log8 "Check if Sideband connection received a RADIUS response from RADIUS server."

				if { $RadCLI(response_payload) ne "" } then {

					#log7 "The Sideband connection successfully received a response from RADIUS server. Aborting further Sideband retransmission processing."

					break

				} else {

					#log7 "The Sideband connection did not received any response from RADIUS server."
					#log6 "Sending a retransmission of the RADIUS Access-Request to RADIUS server ([expr { [clock clicks -milliseconds] - $RadCLI(sideband_connection_timestamp) }] ms)."

					catch { 

						send\
							-status RadCLI(sideband_connection_status)\
							$RadCLI(sideband_connection)\
							$RadCLI(request_payload)

					}

					#log8 "Checking if the RADIUS Access-Request could be successfully retransmitted."

					if { $RadCLI(sideband_connection_status) eq "sent" } then {

						#log8 "The RADIUS Access-Request was successfully retransmitted to RADIUS server."
						#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Sideband_Retransmit_Success" 1

					} else {

						#log6 "A Sideband connection error has occoured. Aborting further Sideband retransmission processing."
						#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Sideband_Retransmit_Failiure" 1

						break

					}

				}

			}

			#log8 "Finish to skip through the list of configured Sideband retransmit intervals. Checking if Sideband connection timeout is already elapsed."

			if { ( $RadCLI(sideband_connection_status) eq "sent" )
			 and ( [clock clicks -milliseconds] - $RadCLI(sideband_connection_timestamp) < $server_config(timeout) ) } then {

				#log8 "The Sideband connection timeout is not elapsed. Waiting the reminder of the configured Sideband timeout value for arrival of the RADIUS response."

				recv \
					-timeout [expr { $server_config(timeout) - ( [clock clicks -milliseconds] - $RadCLI(sideband_connection_timestamp) ) }]\
					-status RadCLI(sideband_connection_status)\
					-peek\
					1\
					$RadCLI(sideband_connection)\
					RadCLI(response_payload)

			}

			#
			# Handler for Sideband RADIUS response processing with retransmits
			#######################################################################

		}

		#log8 "Check if Sideband connection received a response from RADIUS server."

		if { $RadCLI(response_payload) ne "" } then {

			#log6 "Successfully received a response from RADIUS server ([expr { [clock clicks -milliseconds] - $RadCLI(sideband_connection_timestamp) }] ms)."
			#log8 "Loading the entiere RADIUS response from Sideband receive buffer."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Sideband_Receive_Success" 1

			recv \
				-timeout 0\
				$RadCLI(sideband_connection)\
				RadCLI(response_payload)

		} else {

			#######################################################################
			#+ Handler to exit the TCL script
			#

			#log7 "The Sideband connection not received any response from RADIUS server. The received error code is \"[string map {closed "Connection closed" received "Connection timeout" sent "Retransmit timeout" } $RadCLI(sideband_connection_status)]\"."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Sideband_Receive_Failiure" 1

			set server_response(code) 0
			set server_response(message) "The Sideband connection could not receive a response from RADIUS server. Reason: [string map {closed "Connection closed" received "Connection timeout" sent "Retransmit timeout" } $RadCLI(sideband_connection_status)]"

			#log8 "Actively closing the Sideband connection."

			close $RadCLI(sideband_connection)

			#log8 "Exiting the outer \[while\] wrapper."

			break

			#
			# Handler to exit the TCL script
			#######################################################################	

		}

		#
		# Handler for Sideband RADIUS response and selective retransmit processing
		#######################################################################

		#######################################################################
		#+ Handler for Sideband connection close
		#

		#log8 "Actively closing the Sideband connection."

		close $RadCLI(sideband_connection)

		#
		# Handler for Sideband connection close
		#######################################################################

		#######################################################################
		#+ Handler for RADIUS response size verification
		#

		#log8 "Checking if the received RADIUS response meets the minimum RADIUS response size."

		if { [string length $RadCLI(response_payload)] < 20 } then {

			#######################################################################
			#+ Handler to exit the TCL script
			#

			#log6 "The received RADIUS response ([string length $RadCLI(response_payload)]  bytes) is too short for beeing a valid RADIUS response."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Response_TooSmall" 1

			set server_response(code) 0
			set server_response(message) "The RADIUS server did send an invalid response. Reason: response too short"

			#log8 "Exiting the outer \[while\] wrapper."

			break

			#
			# Handler to exit the TCL script
			#######################################################################

		}

		#log7 "The received RADIUS response ([string length $RadCLI(response_payload)] bytes) meets the minimum RADIUS request size."

		#
		# Handler for RADIUS response size verification
		#######################################################################

		#######################################################################
		#+ Handler for RADIUS response encapsulation parsing
		#
		#  0               1               2               3               byte
		#  0                   1                   2                   3
		#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 bits
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
		# |      Code     |  Identifier   |            Length             |
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |                                                               |
		# |                         Authenticator                         |
		# |                           (16 bytes)                          |
		# |                                                               |
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |  Attributes (cont) ...


		#log8 "Extracting the RADIUS request code, ID, length, authenticator and attributes fields."

		binary scan $RadCLI(response_payload) ccSa16a*\
								RadCLI(response_code)\
								RadCLI(response_id)\
								RadCLI(response_length)\
								RadCLI(response_authenticator)\
								RadCLI(response_attributes_field)

		#
		# Handler for RADIUS request encapsulation parsing
		#######################################################################

		#######################################################################
		#+ Handler for RADIUS response ID verification
		#

		#log8 "Checking if the RADIUS response ID is matching our Request ID."

		if { $RadCLI(response_id) ne $RadCLI(request_id) } then {

			#######################################################################
			#+ Handler to exit the TCL script
			#

			#log6 "The RADIUS response ID does not match our RADIUS request ID."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Response_ID_Missmatch" 1

			set server_response(code) 0
			set server_response(message) "The RADIUS server did send an invalid response. Reason: Mismatching RADIUS response ID."

			#log8 "Exiting the outer \[while\] wrapper."

			break

			#
			# Handler to exit the TCL script
			#######################################################################

		}

		#log7 "The RADIUS response ID is matching our Request ID."

		#
		# Handler for RADIUS response ID verification
		#######################################################################

		#######################################################################
		#+ Handler for RADIUS length field verification
		#

		#log8 "Checking if the RADIUS response is received entirely and if the RADIUS response contains paddings."
		#log8 "Unsigning the signed 16-bit integer RADIUS request length field value to support reliable math operation."

		set RadCLI(response_length) [expr { $RadCLI(response_length) & 0xffff } ]

		#log8 "Checking if RADIUS request length field value is less than 4096 bytes and matches the buffered RADIUS response ."

		if { $RadCLI(response_length) > 4096 } then {

			#######################################################################
			#+ Handler to exit the TCL script
			#

			#log4 "Configuration error: The RADIUS response length field value is too large."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Response_TooLarge" 1

			set server_response(code) 0
			set server_response(message) "The RADIUS server did send an invalid response. Reason: RADIUS response is too large"

			#log8 "Exiting the outer \[while\] wrapper."

			break

			#
			# Handler to exit the TCL script
			#######################################################################

		} elseif { $RadCLI(response_length) == [string length $RadCLI(response_payload)] } then {

			#log7 "The RADIUS response length field value matches the buffered RADIUS response."

		} elseif { $RadCLI(response_length) < [string length $RadCLI(response_payload)] } then {

			#log7 "The buffered RADIUS response is larger than the RADIUS request length field value (aka. RFC allowed behavior or receivement of a duplicated UDP datagram)."
			#log8 "Truncating the RADIUS response attributes to match RADIUS request length field value."

			binary scan $RadCLI(response_payload) x20a[expr { $RadCLI(request_length) - 20 }] RadCLI(response_attributes_field)

		} else {

			#######################################################################
			#+ Handler to exit the TCL script
			#

			#log6 "The received RADIUS response is shorter than the RADIUS request length field value. Discarding the malformed / fragmented RADIUS response."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Response_Fragmented" 1

			set server_response(code) 0
			set server_response(message) "The RADIUS server did send an invalid response. Reason: malformed / fragmented response"


			#log8 "Exiting the outer \[while\] wrapper."

			break

			#
			# Handler to exit the TCL script
			#######################################################################

		}

		#
		# Handler for RADIUS length field verification
		#######################################################################

		#######################################################################
		#+ Handler for RADIUS reponse authenticator verification
		#

		#log8 "Calculating the response authenticator verification value to proof the origin of the received response."

		set RadCLI(response_authenticator_verification) [md5\
									[binary format ccSa16a*a*\
												$RadCLI(response_code)\
												$RadCLI(response_id)\
												$RadCLI(response_length)\
												$RadCLI(request_authenticator)\
												$RadCLI(response_attributes_field)\
												$server_config(shared_key)\
									]\
								]

		#log8 "Checking if the calculated and the received response authenticator value is the same."

		if { $RadCLI(response_authenticator) ne $RadCLI(response_authenticator_verification) } then {

			#######################################################################
			#+ Handler to exit the TCL script
			#

			#log6 "The RADIUS response authenticator value could not be verified."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Response_Auth_Missmatch" 1

			set server_response(code) 0
			set server_response(message) "The RADIUS server did send an invalid response. Reason: Invalid RADIUS response authenticator"

			#log8 "Exiting the outer \[while\] wrapper."

			break

			#
			# Handler to exit the TCL script
			#######################################################################

		}

		#log7 "The received RADIUS response authenticator could be successfully verified."

		#
		# Handler for RADIUS reponse authenticator verification
		#######################################################################

		#######################################################################
		#+ Handler for RADIUS response attribute verification and extraction
		#
		# 0               1               2               3               4 byte
		# 0                   1                   2                   3
		# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 bits
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |  Attr1-Code   |  Attr1-Length |         Attr1-Value           |
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |  Attr1-Value (cont) ...       |  AttrN-Code   |  AttrN-Length |
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |                        AttrN-Value (cont) ...                 |
		# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		# |  AttrN-Value (cont) ...

		#log8 "Checking if the RADIUS response contains any RADIUS attribute value pairs."

		if { $RadCLI(response_attributes_field) ne "" } then {

			#log8 "The RADIUS response contains RADIUS attribute value pairs. Calculating the total length of request attributes field."

			set RadCLI(response_attributes_field_length) [expr { $RadCLI(response_length) - 20 }]

			#log8 "Verifying the integrity of contained response attributes and extracting their IDs and values by stepping through the RADIUS response attribute field."

			for { set RadCLI(response_attributes_field_offset) 0 } { $RadCLI(response_attributes_field_offset) + 3 <= $RadCLI(response_attributes_field_length) } { incr RadCLI(response_attributes_field_offset) $RadCLI(response_attribute_length) } {

				#log8 "Extracting the singned 8-bit integer attribute ID and length value of the next RADIUS request attributes field."

				binary scan $RadCLI(response_attributes_field) x$RadCLI(response_attributes_field_offset)cc RadCLI(response_attribute_id) RadCLI(response_attribute_length)

				#log8 "Unsigning the signed 8-bit integer length value and checking if the attribute length value is at least 3 bytes long."

				if { [set RadCLI(response_attribute_length) [expr { $RadCLI(response_attribute_length) & 0xff } ]] < 3 } then {

					#log7 "The attribute length value is invalid. Aborting further attribute processing."

					break

				}

				#log8 "The extracted attribute length value is valid. Extracting the attribute value based on the attribute length value."

				binary scan $RadCLI(response_attributes_field) x$RadCLI(response_attributes_field_offset)x2a[expr { $RadCLI(response_attribute_length) - 2 }] RadCLI(response_attribute_value)

				#log8 "Unsigning the signed 8-bit integer attribute id value"

				set RadCLI(response_attribute_id) [expr { $RadCLI(response_attribute_id) & 0xff } ]

				#log8 "Checking if the currently processed attribute contains a HMAC-based Message Authenticator attribute."

				if { $RadCLI(response_attribute_id) == 80 } then {

					#######################################################################
					#+ Handler for HMAC-based message authenticator attribute verification
					#

					#log8 "The RADIUS response contains a HMAC-based message authenticator attribute. Extracting the leading and trailing attributes for HMAC verification checksum construction."

					binary scan $RadCLI(response_attributes_field) a$RadCLI(response_attributes_field_offset)x18a* RadCLI(response_attributes_field_1) RadCLI(response_attributes_field_2)

					#log8 "Performing HMAC-MD5 calculation on the RADIUS request with initialized Message Authenticator attribute (16 bytes of 0x00) using the servers shared key."

					set RadCLI(response_hmac_verification) [CRYPTO::sign -alg hmac-md5 -key $server_config(shared_key)\
																	[binary format ccSa16a*cca*a*\
																					$RadCLI(response_code)\
																					$RadCLI(response_id)\
																					$RadCLI(response_length)\
																					$RadCLI(request_authenticator)\
																					$RadCLI(response_attributes_field_1)\
																					80\
																					18\
																					"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
																					$RadCLI(response_attributes_field_2)\
																	]\
										]

					#log8 "Comparing the HMAC-MD5 calculation result with the received attribute value."

					if { $RadCLI(response_hmac_verification) eq $RadCLI(response_attribute_value) } then {

						#log7 "The HMAC-MD5 signature could be sucessfully verified."
						#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Response_Attributes_HMAC_Verified" 1

					} else {

						#log7 "The HMAC-MD5 signature could not be verified."
						#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Response_Attributes_HMAC_Failure" 1

						#log8 "Aborting further attribute processing."

						break

					}

					#
					# Handler for HMAC-based message authenticator attribute verification
					#######################################################################

				} else {

					#log8 "Checking if the attribute ID \"$RadCLI(response_attribute_id)\" has already been extracted to support duplicated RADIUS response attributes."

					if { not [info exists RadCLI(response_attribute_index_$RadCLI(response_attribute_id))] } then {

						#log8 "The attribute ID \"$RadCLI(response_attribute_id)\" has not been extracted before. Initializing attribute index to \"0\" while adding the currently processed RADIUS response attribute to the server_response(avp_*) array."   

						set server_response(avp_$RadCLI(response_attribute_id)_[set RadCLI(response_attribute_index_$RadCLI(response_attribute_id)) 0]) $RadCLI(response_attribute_value)

					} else {

						#log8 "The attribute ID \"$RadCLI(response_attribute_id)\" has already been extracted. Increasing the attribute index to \"[expr { $RadCLI(response_attribute_index_$RadCLI(response_attribute_id)) + 1}]\" while adding the currently processed RADIUS response attribute to the server_response(avp_*) array."   

						set server_response(avp_$RadCLI(response_attribute_id)_[incr RadCLI(response_attribute_index_$RadCLI(response_attribute_id))]) $RadCLI(response_attribute_value)

					}

					#log7 "Successfully extracted the currently processed RADIUS response attribute and stored it into \$server_response(avp_$RadCLI(response_attribute_id)_$RadCLI(response_attribute_index_$RadCLI(response_attribute_id)))"

				}

			}

			if { $RadCLI(response_attributes_field_offset) != $RadCLI(response_attributes_field_length) } then {

				#######################################################################
				#+ Handler to exit the TCL script
				#

				#log6 "The Radius response attributes are malformated."
				#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Response_Attributes_Malformated" 1

				set server_response(code) 0
				set server_response(message) "The RADIUS server did send an invalid response. Reason: Malformed RADIUS response attributes"

				#log8 "Exiting the outer \[while\] wrapper."

				break

				#
				# Handler to exit the TCL script
				#######################################################################

			}

			#log7 "Finished to process the attributes. The RADIUS attribute encapsulation is correctly constructed."

		} else {

			#log7 "The RADIUS response does not contain any RADIUS attribute value pairs."

		}

		#
		# Handler for RADIUS response attribute verification and extraction
		#######################################################################

		#######################################################################
		#+ Handler for RADIUS request code evaluation
		#

		#log8 "Evaluate the RADIUS request code..."

		if { $RadCLI(response_code) == 2 } then {

			#log5 "The authentication for username \"$client_request(username)\" was ACCEPTED by RADIUS server \"$server_config(address)\"."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Response_ACCEPT" 1

			set server_response(code) 2
			set server_response(message) "ACCEPT"

		} elseif { $RadCLI(response_code) == 3 } then {

			#log5 "The authentication for username \"$client_request(username)\" was REJECTED by RADIUS server \"$server_config(address)\"."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Response_REJECT" 1

			set server_response(code) 3
			set server_response(message) "REJECT"

		} elseif { $RadCLI(response_code) == 11 } then {

			#log6 "The authentication for username \"$client_request(username)\" requires additional authentication information for RADIUS server \"$server_config(address)\"."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Response_CHALLENGE" 1

			set server_response(code) 11
			set server_response(message) "CHALLENGE"

		} else {

			#######################################################################
			#+ Handler to exit the TCL script
			#

			#log4 "Configuration error: The received RADIUS response code is not an authentication specific."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadCLI$RadCLI(istats_label)_Response_UNKNOWN" 1

			set server_response(code) 0
			set server_response(message) "The RADIUS server did send an invalid response. Reason: Unsupported RADIUS response code"

			#log8 "Exiting the outer \[while\] wrapper."

			break

			#
			# Handler to exit the TCL script
			#######################################################################

		}

		#
		# Handler for RADIUS request code evaluation
		#######################################################################

		#request #######################################################################
		#request #+ Handler for RADIUS response logging
		#request #

		#requestlog "[string repeat "\u0023" 30] RADIUS Response [string repeat "\u0023" 30]"
		#requestlog "Username    =  $client_request(username)"
		#requestlog "Result Code =  $server_response(code)"
		#requestlog "Result MSG  =  $server_response(message)"
		#request foreach { RadCLI(response_avp) } [lsort [array names response "avp_*"]] {
			#requestlog "AttributeID [getfield $RadCLI(response_avp) "avp_" 2] = uriencoded([URI::encode $server_response($RadCLI(response_avp))])"
		#request }
		#requestlog "[string repeat "\u0023" 30] RADIUS Response [string repeat "\u0023" 30]"

		#request #
		#request # Handler for RADIUS response logging
		#request #######################################################################

		#######################################################################
		#+ Handler to exit the TCL script
		#

		#log8 "Exiting the outer \[while\] wrapper."

		break

		#
		# Handler to exit the TCL script
		#######################################################################

	}

	#
	# Handler for outer [while] wrapper
	#######################################################################

	#log6 "Finished to process the RADIUS client request for username \"$client_request(username)\" to server \"$server_config(address)\""

	#######################################################################
	#+ Handler for variable clearance
	#

	#cleanup #log8 "Clearing user provided client_request() variables to support consecutive executions."

	#cleanup unset -nocomplain client_request(attributes)

	#log8 "Clearing all RadCLI() variables to free memory and to support consecutive executions."

	unset -nocomplain RadCLI

	#
	# Handler for variable clearance
	#######################################################################

	#
	# Handler for RADIUS client execution
	#######################################################################
	#======================================================================

}

	#======================================================================
	#######################################################################
	#+ Execution of TCL script pre-compiler
	#

	if { $RadCLI_compiler(enable) == 1 } then {

		#######################################################################
		#+ Handler to define the TCL pre-compiler search/replace map
		#

		log -noname local0.debug "RadCLI compiler : (TMM[TMM::cmp_unit]): Initializing RADIUS client script optimization and pre-compiling."

		set RadCLI_compiler(replace_map) ""

		log -noname local0.debug "RadCLI compiler : (TMM[TMM::cmp_unit]): Enumerating the enabled RADIUS client script optimizations."

		if { $RadCLI_compiler(compression_enable) == 1 } then {

			log -noname local0.debug "RadCLI compiler : (TMM[TMM::cmp_unit]): RADIUS client script syntax compression is enabled. Importing variable compression compile map."

			# Note: Sorted in alphabetical order where each variable is truncated to a unique abbreviation to speed up variable lookups (cpu and memory savings).

			lappend RadCLI_compiler(replace_map) \
				" \]"						"\]"		\
				RadCLI(encryption_iv)				"rc(iv)"	\
				RadCLI(encryption_key_64bit_chunk_1)		"rc(k641)"	\
				RadCLI(encryption_key_64bit_chunk_2)		"rc(k642)"	\
				RadCLI(encrypted_password)			"rc(ep)"	\
				RadCLI(encrypted_password_64bit_chunks)		"rc(e64)"	\
				RadCLI(istats_label)				"rc(il)"	\
				RadCLI(plaintext_password_64bit_chunks)		"rc(p64)"	\
				RadCLI(plaintext_password_64bit_chunk_1)	"rc(p641)"	\
				RadCLI(plaintext_password_64bit_chunk_2)	"rc(p642)"	\
				RadCLI(response_code)				"rc(rc)"	\
				RadCLI(response_attributes_field)		"rc(raf)"	\
				RadCLI(response_attributes_field_1)		"rc(raf1)"	\
				RadCLI(response_attributes_field_2)		"rc(raf2)"	\
				RadCLI(response_attributes_field_length)	"rc(rafl)"	\
				RadCLI(response_attributes_field_offset)	"rc(rafo)"	\
				RadCLI(response_attribute_id)			"rc(rai)"	\
				RadCLI(response_attribute_length)		"rc(ral)"	\
				RadCLI(response_attribute_value)		"rc(rav)"	\
				RadCLI(response_authenticator)			"rc(ra)"	\
				RadCLI(response_authenticator_verification)	"rc(rav)"	\
				RadCLI(response_avp)				"rc(ravp)"	\
				RadCLI(response_hmac_verification)		"rc(rhv)"	\
				RadCLI(response_id)				"rc(ri)"	\
				RadCLI(response_length)				"rc(rl)"	\
				RadCLI(response_payload)			"rc(rp)"	\
				RadCLI(response_attributes_field_length)	"rc(rafl)"	\
				RadCLI(response_attributes_field_offset)	"rc(rafo)"	\
				RadCLI(request_attribute_format)		"rc(qaf)"	\
				RadCLI(request_attribute_type)			"rc(qat)"	\
				RadCLI(request_attribute_value)			"rc(qav)"	\
				RadCLI(request_attributes_field)		"rc(qafi)"	\
				RadCLI(request_authenticator)			"rc(qa)"	\
				RadCLI(request_id)				"rc(qi)"	\
				RadCLI(request_length)				"rc(ql)"	\
				RadCLI(request_timestamp)			"rc(rt)"	\
				RadCLI(request_payload)				"rc(qp)"	\
				RadCLI(sideband_connection)			"rc(sc)"	\
				RadCLI(sideband_connection_status)		"rc(scs)"	\
				RadCLI(sideband_connection_timestamp)		"rc(sct)"	\
				RadCLI(sideband_retransmit)			"rc(sr)"	\
				"ACCEPT"					"ACCEPT"	\
				"CHALLENGE"					"CHALLENGE"	\
				"REJECT"					"REJECT"	\
				RadPOL(request_timestamp)			RadPOL(request_timestamp)	\
				server_config(address)				server_config(address)		\
				server_config(shared_key)			server_config(shared_key)	\
				server_config(timeout)				server_config(timeout)		\
				server_config(retransmits)			server_config(retransmits)	\
				client_request(username)			client_request(username)	\
				client_request(password)			client_request(password)	\
				client_request(attributes)			client_request(attributes)	\
				server_response(code)				server_response(code)		\
				server_response(message)			server_response(message)	\
				server_response(avp_				server_response(avp_		\
				"unset -nocomplain server_response"		"unset -nocomplain server_response" \
				"unset -nocomplain RadCLI"			"unset -nocomplain rc"

		}

		if { $RadCLI_compiler(log_enable) == 1 } then {

			log -noname local0.debug "RadCLI compiler : (TMM[TMM::cmp_unit]): RADIUS client script logging is enabled. Constructing the log-prefix."

			set RadCLI_compiler(log_prefix) [string map $RadCLI_compiler(replace_map) "$RadCLI_compiler(log_prefix)\$RadCLI(request_timestamp) :"]

			log -noname local0.debug "RadCLI compiler : (TMM[TMM::cmp_unit]): Importing compile map for log level = \"$RadCLI_compiler(log_level)\"."

			for { set RadCLI_compiler(x) 0 } { $RadCLI_compiler(x) <= $RadCLI_compiler(log_level) } { incr RadCLI_compiler(x) } {
				switch -exact -- $RadCLI_compiler(x) {
					0 { lappend RadCLI_compiler(replace_map) "#log$RadCLI_compiler(x) \"" "log -noname local0.emerg \"$RadCLI_compiler(log_prefix) " }
					1 { lappend RadCLI_compiler(replace_map) "#log$RadCLI_compiler(x) \"" "log -noname local0.alert \"$RadCLI_compiler(log_prefix) " }
					2 { lappend RadCLI_compiler(replace_map) "#log$RadCLI_compiler(x) \"" "log -noname local0.crit \"$RadCLI_compiler(log_prefix) " }
					3 { lappend RadCLI_compiler(replace_map) "#log$RadCLI_compiler(x) \"" "log -noname local0.error \"$RadCLI_compiler(log_prefix) " }
					4 { lappend RadCLI_compiler(replace_map) "#log$RadCLI_compiler(x) \"" "log -noname local0.warn \"$RadCLI_compiler(log_prefix) " }
					5 { lappend RadCLI_compiler(replace_map) "#log$RadCLI_compiler(x) \"" "log -noname local0.notice \"$RadCLI_compiler(log_prefix) " }
					6 { lappend RadCLI_compiler(replace_map) "#log$RadCLI_compiler(x) \"" "log -noname local0.info \"$RadCLI_compiler(log_prefix) " }
					7 { lappend RadCLI_compiler(replace_map) "#log$RadCLI_compiler(x) \"" "log -noname local0.debug \"$RadCLI_compiler(log_prefix) " }
					8 { lappend RadCLI_compiler(replace_map) "#log$RadCLI_compiler(x) \"" "log -noname local0.debug \"$RadCLI_compiler(log_prefix) " }
				}
			}
		}

		if { $RadCLI_compiler(enable_input_validation) == 1 } then {

			log -noname local0.debug "RadCLI compiler : (TMM[TMM::cmp_unit]): RADIUS client input validation is enabled. Importing compile map to enable input validation."

			lappend RadCLI_compiler(replace_map) "#input " ""

		}

		if { $RadCLI_compiler(request_tracing_enable) == 1 } then {

			log -noname local0.debug "RadCLI compiler : (TMM[TMM::cmp_unit]): RADIUS client request tracing is enabled. Importing compile map to enable RADIUS request tracing."

			lappend RadCLI_compiler(replace_map) "#requestlog \"" "log -noname local0.debug \"$RadCLI_compiler(log_prefix)"
			lappend RadCLI_compiler(replace_map) "#request " ""

		}

		if { $RadCLI_compiler(istats_enable) == 1 } then {

			log -noname local0.debug "RadCLI compiler : (TMM[TMM::cmp_unit]): RADIUS client statistics are enabled. Importing compile map to enable istats collectors."

			lappend RadCLI_compiler(replace_map) "#istats " ""
		}

		if { $RadCLI_compiler(enable_variable_cleanup) == 1 } then {

			log -noname local0.debug "RadCLI compiler : (TMM[TMM::cmp_unit]): RADIUS client variable cleanup is enabled. Importing compile map to enable variable cleanup."

			lappend RadCLI_compiler(replace_map) "#cleanup " ""

		}

		#
		# Handler to define the TCL pre-compiler search/replace map
		#######################################################################

		#######################################################################
		#+ Handler to pre-compile the RADIUS Client Processor TCL script
		#

		log -noname local0.debug "RadCLI compiler : (TMM[TMM::cmp_unit]): Applying the search/replace map to the original RADIUS Client Processor TCL script."

		set static::RadCLI_Processor [string map $RadCLI_compiler(replace_map) $static::RadCLI_Processor]

		if { $RadCLI_compiler(remove_unnecessary_lines) } then {

			log -noname local0.debug "RadCLI compiler : (TMM[TMM::cmp_unit]): RADIUS ClientProcessor TCL script unnecessary line cleanup is enabled. Parsing the TCL script line by line to remove unnecessary lines."

			set RadCLI_compiler(bunch_of_code) ""

			foreach RadCLI_compiler(line_of_code) [split $static::RadCLI_Processor "\n"] {

				switch -glob -- $RadCLI_compiler(line_of_code) {

					"*	#+*" {

						# Keep the script line with important comments
						set RadCLI_compiler(line_feed) [substr $RadCLI_compiler(line_of_code) 0 "#"]
						lappend RadCLI_compiler(bunch_of_code) "" "$RadCLI_compiler(line_feed)#" $RadCLI_compiler(line_of_code) "$RadCLI_compiler(line_feed)#" ""

					}
					"" - "*	#*" {

						# Remove the empty or unnessesary script lines

					}
					default {

						# Keep the script line with necessary code
						lappend RadCLI_compiler(bunch_of_code) $RadCLI_compiler(line_of_code)

					}

				}

			}

			set static::RadCLI_Processor [join $RadCLI_compiler(bunch_of_code) "\n"]

		}

		log -noname local0.debug "RadCLI compiler : (TMM[TMM::cmp_unit]): Finished to pre-compile the RADIUS Client Processor TCL script. Storing it to \"\$static::RadCLI_Processor\"."

		#
		# Handler to pre-compile the RADIUS Client Processor TCL script
		#######################################################################

	}

	unset -nocomplain RadCLI_compiler

	#
	# Execution of TCL script pre-compiler
	#######################################################################
	#======================================================================

}
