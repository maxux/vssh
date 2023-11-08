import maxux.vssh

x := vssh.new("10.241.0.240", 22)!
println(x.fingerprint())
println(x.authenticate(.agent, "root", "")!)

y := vssh.new("10.241.0.230", 22)!
println(y.fingerprint())
println(y.authenticate(.keyboard_interactive, "vssh", "aaaa")!)
