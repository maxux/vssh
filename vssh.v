[translated]
module vssh

#include "@VMODROOT/vssh.h"

#flag @VMODROOT/vssh.o
#flag -lssh2
#flag -DVSSH_NO_MAIN

fn C.ssh_initialize() &C.ssh_t

fn C.ssh_connect(&C.ssh_t, &u8, &u8) int

fn C.ssh_error(&C.ssh_t)

fn C.ssh_error_str(&C.ssh_t) &char

fn C.ssh_fingerprint_hex(&C.ssh_t) &char

fn C.ssh_handshake(&C.ssh_t) int

fn C.ssh_authenticate_agent(&C.ssh_t, &u8) int

fn C.ssh_authenticate_password(&C.ssh_t, &u8, &u8) int

fn C.ssh_authenticate_kb_interactive(&C.ssh_t, &u8, &u8) int

fn C.ssh_execute(&C.ssh_t, &u8) int

fn C.ssh_session_disconnect(&C.ssh_t)

pub enum Authentication {
	agent
	password
	keyboard_interactive
}

struct SSH2 {
	kntxt &C.ssh_t
	host string
	port string
	user string
	authenticated int
}

fn ssh_fetch_error(ssh SSH2) string {
	s := C.ssh_error_str(ssh.kntxt)
	return unsafe { s.vstring() }
}

pub fn new(host string, port int) !SSH2 {
	ssh := SSH2{}

	ssh.kntxt = C.ssh_initialize()
	ssh.authenticated = -1

	sport := "${port}"

	val := C.ssh_connect(ssh.kntxt, host.str, sport.str)
	if val > 0 {
		return error(ssh_fetch_error(ssh))
	}
	
	val = C.ssh_handshake(ssh.kntxt)
	if val > 0 {
		return error(ssh_fetch_error(ssh))
	}
	
	return ssh
}

pub fn (s SSH2) fingerprint() string {
	f := C.ssh_fingerprint_hex(s.kntxt)
	return unsafe { f.vstring() }
}

fn (s SSH2) authenticate_agent(user string) !bool {
	println("-- authenticating using agent")
	if C.ssh_authenticate_agent(s.kntxt, user.str) > 0 {
		return error(ssh_fetch_error(s))
	}

	s.authenticated = Authentication.agent
	return true
}

fn (s SSH2) authenticate_password(user string, pass string) !bool {
	println("-- authenticating using password")
	if C.ssh_authenticate_password(s.kntxt, user.str, pass.str) > 0 {
		return error(ssh_fetch_error(s))
	}

	s.authenticated = Authentication.password
	return true
}

fn (s SSH2) authenticate_kb_interactive(user string, pass string) !bool {
	println("-- authenticating using keyboard interactive ")
	if C.ssh_authenticate_kb_interactive(s.kntxt, user.str, pass.str) > 0 {
		return error(ssh_fetch_error(s))
	}

	s.authenticated = Authentication.keyboard_interactive
	return true
}


pub fn (s SSH2) authenticate(method Authentication, user string, pass string) !bool {
	if method == .agent {
		return s.authenticate_agent(user)
	}

	// works on legacy devices, like router os, etc.
	if method == .password {
		return s.authenticate_password(user, pass)
	}

	// password method for any new system (openssh, etc.)
	if method == .keyboard_interactive {
		return s.authenticate_kb_interactive(user, pass)
	}

	return error("unknown authenticating method")
}

pub fn test() {
	println("Hello world")
}
