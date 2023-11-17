import maxux.vssh

x := vssh.new("10.241.0.240", 22)!
println(x.fingerprint())
x.authenticate(.agent, "root", "")!
x.execute("uname -a")!
x.stream("dmidecode")!
x.disconnect()

y := vssh.new("10.241.0.230", 22)!
println(y.fingerprint())
y.authenticate(.keyboard_interactive, "vssh", "aaaa")!
y.disconnect()

