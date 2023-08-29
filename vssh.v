[translated]
module vssh

#include "@VMODROOT/vssh.h"

#flag @VMODROOT/vssh.o
#flag -lssh2
#flag -DVSSH_NO_MAIN

pub fn test() {
	println("Hello world")
}
