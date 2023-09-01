[translated]
module vssh

#include "@VMODROOT/vssh.h"

#flag @VMODROOT/vssh.o
#flag -lssh2
#flag -DVSSH_NO_MAIN

pub enum Authentication {
	agent
	password
}

struct SSH2 {
	ssh &C.ssh_t
}

pub fn new(method Authentication, host string, user string, password string) !SSH2 {
	ssh := SSH2{}

	if method == .agent {
		println("SSH AGENT")
	}

	if method == .password {
		println("BY PASSWORD")
	}

	println(method)
	println(user)
	println(password)

	return ssh
}

pub fn test() {
	println("Hello world")
}
