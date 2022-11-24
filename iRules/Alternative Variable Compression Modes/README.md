# About

The included TCL-PreCompiler of the RADIUS Client Stack optimizes during a `RULE_INIT` event the run-time used `$RadCLI(array_label)` names of the RADIUS Client Processor. 

The samples below outlining different Variable Compression Modes of the TCL-PreCompiler and explaining their pros and cons.

# Mode 1: Disable Variable Compression

If you disable the variable compression option within the PreCompiler settings (via `set RadCLI_compiler(compression_enable) 0`), the TCL-PreCompiler won't change the rather long but human friendly `$RadCLI(array_label)` variable names during the `RULE_INIT` event.

The performance of the RADIUS Client Stack will be slightly degrated because the creation, maintenance and lockup of those rather long `$RadCLI(array_label)` variable names requires additional CPU cycles. The benefit of this mode is a simplyfied development and iRule debugging. You will always know what the purpose of those human friendly `$RadCLI(array_label)` variables are - within your code and when a TCL-Stack-Trace happens.  

### Disabled PreCompiler Compression Results:

Below is an uncompressed code snipped fetched from the RADIUS Client Processor.

```
#
#+ Handler for RADIUS password attribute encryption
#

if { [string length $client_request(password)] % 16 > 0 } then {
	set client_request(password) [binary format a[expr { ( int( [string length $client_request(password)] / 16 ) + 1 ) * 16 }] $client_request(password)]
}
if { [string length $client_request(password)] == 16 } then {
	binary scan $client_request(password) WW RadCLI(plaintext_password_64bit_chunk_1) RadCLI(plaintext_password_64bit_chunk_2)
	binary scan [md5 "$server_config(shared_key)$RadCLI(request_authenticator)"] WW RadCLI(encryption_key_64bit_chunk_1) RadCLI(encryption_key_64bit_chunk_2)
	set RadCLI(encrypted_password) [binary format WW [expr { $RadCLI(plaintext_password_64bit_chunk_1) ^ $RadCLI(encryption_key_64bit_chunk_1) }] [expr { $RadCLI(plaintext_password_64bit_chunk_2) ^ $RadCLI(encryption_key_64bit_chunk_2) }] ]
} else {
	binary scan $client_request(password) W* RadCLI(plaintext_password_64bit_chunks)
	set RadCLI(encryption_iv) $RadCLI(request_authenticator)
	foreach { RadCLI(plaintext_password_64bit_chunk_1) RadCLI(plaintext_password_64bit_chunk_2) } $RadCLI(plaintext_password_64bit_chunks) {
		binary scan [md5 "$server_config(shared_key)$RadCLI(encryption_iv)"] WW RadCLI(encryption_key_64bit_chunk_1) RadCLI(encryption_key_64bit_chunk_2)
		lappend RadCLI(encrypted_password_64bit_chunks) [expr { $RadCLI(plaintext_password_64bit_chunk_1) ^ $RadCLI(encryption_key_64bit_chunk_1) }] [expr { $RadCLI(plaintext_password_64bit_chunk_2) ^ $RadCLI(encryption_key_64bit_chunk_2) }]
		set RadCLI(encryption_iv) [binary format W* [lrange $RadCLI(encrypted_password_64bit_chunks) end-1 end]]
	}
	set RadCLI(encrypted_password) [binary format W* $RadCLI(encrypted_password_64bit_chunks)]
}
```

# Mode 2: Enable Variable Compression with "unique" mappings

If you enable the included variable compression option within the PreCompiler settings (via `set RadCLI_compiler(compression_enable) 1`), the TCL-PreCompiler will change the rather long and human friendly `$RadCLI(array_label)` variable names to shrinked variable names (e.g. `$rc(al)`) during the `RULE_INIT` event. 

The performance of the RADIUS Client Stack will be slightly optimized because the creation, maintenance and lockup of those short variable name requires less CPU cycles and memory. The downside of this mode is a more difficult iRule debugging experience, because the code you write and the executed code is now different. If a TCL stack trace happens, you may need to use the compression map to become able to translate the short run-time varible names back to their long form to spot the problem in the code you write. But in the end this should not a big deal...

### "unique" PreCompiler Compression Map:

The compression map of this mode is sorted in alphabetical order where each human friendly variable is getting trunkated to a short and unique abbreviation. The variable name which are getting exposed to custom iRule solutions (e.g. `server_config()`, `client_request()` and `server_response()` are not compressed. 

```

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
```

### "unique" PreCompiler Compression Result:

Below is an compressed code snipped fetched from the RADIUS Client Processor. The used compression map was set to "unique".

```
#
#+ Handler for RADIUS password attribute encryption
#

if { [string length $client_request(password)] % 16 > 0 } then {
	set client_request(password) [binary format a[expr { ( int( [string length $client_request(password)] / 16 ) + 1 ) * 16 }] $client_request(password)]
}
if { [string length $client_request(password)] == 16 } then {
	binary scan $client_request(password) WW rc(p641) rc(p642)
	binary scan [md5 "$server_config(shared_key)$rc(qa)"] WW rc(k641) rc(k642)
	set rc(ep) [binary format WW [expr { $rc(p641) ^ $rc(k641) }] [expr { $rc(p642) ^ $rc(k642) }]]
} else {
	binary scan $client_request(password) W* rc(p64)
	set rc(iv) $rc(qa)
	foreach { rc(p641) rc(p642) } $rc(p64) {
		binary scan [md5 "$server_config(shared_key)$rc(iv)"] WW rc(k641) rc(k642)
		lappend rc(e64) [expr { $rc(p641) ^ $rc(k641) }] [expr { $rc(p642) ^ $rc(k642) }]
		set rc(iv) [binary format W* [lrange $rc(e64) end-1 end]]
	}
	set rc(ep) [binary format W* $rc(e64)]
}
```

# Mode 3: Enable Variable Compression with "shared" mappings

You may use the experimental "shared" compression mode by replacing the default "unique" compression map at the bottom of the provided TCL PreCompiler section with a "shared" compression map that optimizes the run-time executed code to its maximum. 

The "shared" compression map consolidates one or more rather long and human friendly `$RadCLI(array_label)` variable names to a combined single letter variable name (e.g. `${1}`) to reduce the total number of variable creations, the required time to lookup a given variable and the memory footprint of all used variables to an absolute minimum.

The downside of this mode is an absolute nightmarish iRule debugging experience. If a TCL stack trace happens an complains problems with lets say variable `${2}` you will most likely not be able to translate those shared variable names back to the rather long and human friendly `$RadCLI(array_label)` original variable name. One or more different `$RadCLI(array_label)` variables may be mapped to the single letter variable name `${2}`. 

### "shared" PreCompiler Compression Map:

The compression map of this mode is generated by reading and analyzing the original code of the RADIUS Client Processor from top to the button. 

Whenever a `$RadCLI(something)` variable is used for the first time, it gets assigned the next free entry of a single letter pool (e.g. `$RadCLI(someting)` becomes `${1}` and `$RadCLI(someting_else)` becomes `${2}`). The usage of such single letter variable names is considered the most CPU and memory friendly choice.  

Whenever a given `$RadCLI(something)` variable is not used anymore till the end of RADIUS Client Processor (aka. it has done its job!), its reserved entry in the single letter pool will get released, so that the very next `$RadCLI(something_different)` variable used for the first time can reuse the already initialized single letter varibale of `${1}`. This approach would eleminate the need to create a new variable for each unique variable usecase (creation of variables costs CPU and Memory) and also immediately free the memory used to hold the now obsolete variable data (costs Memory if variable data remains in the stack longer than needed) without manually releasing it (costs CPU to release the data explicitly via `[unset]`). 

Recycling of varibale names (respectivily their internal memory links within the TCL runtime) is therefor the key to optimize the last nimbles of an already highly optimized TCL code.


```

# Note: The variable names are sorted in the order of appearance and getting compressed to the next free entry of a single letter pool.
#       If the variable is not used anymore, its number will be added back to the pool ready for reuse (cpu savings).
#       If a variable had previously stored large amounts of data, the variable will be reused preferred (memory savings).
#	Variable "a" and "b" are lappend'ed without initializing an empty value. A manual unset is required at the end of the script to support chained executions.

lappend RadCLI_compiler(replace_map) \
	" \]"						"\]"	\
	RadCLI(request_timestamp)			"{0}"	\
	RadCLI(istats_label)				"{1}"	\
	RadCLI(request_id)				"{2}"	\
	RadCLI(request_authenticator)			"{3}"	\
	RadCLI(plaintext_password_64bit_chunks)		"{4}"	\
	RadCLI(encryption_iv)				"{5}"	\
	RadCLI(plaintext_password_64bit_chunk_1)	"{6}"	\
	RadCLI(plaintext_password_64bit_chunk_2)	"{7}"	\
	RadCLI(encryption_key_64bit_chunk_1)		"{8}"	\
	RadCLI(encryption_key_64bit_chunk_2)		"{9}"	\
	RadCLI(encrypted_password_64bit_chunks)		"{a}"	\
	RadCLI(encrypted_password)			"{10}"	\
	RadCLI(request_attribute_type)			"{4}"	\
	RadCLI(request_attribute_format)		"{5}"	\
	RadCLI(request_attribute_value)			"{6}"	\
	RadCLI(request_attributes_field)		"{b}"	\
	RadCLI(request_length)				"{10}"	\
	RadCLI(request_payload)				"{9}"	\
	RadCLI(sideband_connection)			"{8}"	\
	RadCLI(sideband_connection_status)		"{7}"	\
	RadCLI(sideband_connection_timestamp)		"{6}"	\
	RadCLI(sideband_retransmit)			"{5}"	\
	RadCLI(response_payload)			"{4}"	\
	RadCLI(response_code)				"{5}"	\
	RadCLI(response_id)				"{6}"	\
	RadCLI(response_length)				"{7}"	\
	RadCLI(response_authenticator)			"{8}"	\
	RadCLI(response_attributes_field)		"{9}"	\
	RadCLI(response_authenticator_verification)	"{10}"	\
	RadCLI(response_attributes_field_offset)	"{4}"	\
	RadCLI(response_attributes_field_length)	"{8}"	\
	RadCLI(response_attribute_id)			"{a}"	\
	RadCLI(response_attribute_length)		"{b}"	\
	RadCLI(response_attribute_value)		"{2}"	\
	RadCLI(response_attributes_field_1)		"{a}"	\
	RadCLI(response_attributes_field_2)		"{10}"	\
	RadCLI(response_hmac_verification)		"{10}"	\
	RadCLI(response_avp)				"{9}"	\
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
	"unset -nocomplain RadCLI"			"unset -nocomplain a b"

```

### "shared" PreCompiler Compression Result:

Below is an compressed code snipped fetched from the RADIUS Client Processor. The used compression map was set to "shared".

```
#
#+ Handler for RADIUS password attribute encryption
#

if { [string length $client_request(password)] % 16 > 0 } then {
	set client_request(password) [binary format a[expr { ( int( [string length $client_request(password)] / 16 ) + 1 ) * 16 }] $client_request(password)]
}
if { [string length $client_request(password)] == 16 } then {
	binary scan $client_request(password) WW {6} {7}
	binary scan [md5 "$server_config(shared_key)${3}"] WW {8} {9}
	set {10} [binary format WW [expr { ${6} ^ ${8} }] [expr { ${7} ^ ${9} }]]
} else {
	binary scan $client_request(password) W* {4}
	set {5} ${3}
	foreach { {6} {7} } ${4} {
		binary scan [md5 "$server_config(shared_key)${5}"] WW {8} {9}
		lappend {a} [expr { ${6} ^ ${8} }] [expr { ${7} ^ ${9} }]
		set {5} [binary format W* [lrange ${a} end-1 end]]
	}
	set {10} [binary format W* ${a}]
}
```
