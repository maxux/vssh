import maxux.vssh

vssh.test()

x := vssh.new(.agent, "", "hello", "")!
y := vssh.new(.password, "", "hello", "world")!
