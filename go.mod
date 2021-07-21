module github.com/AudriusButkevicius/pfilter

go 1.15

require (
	github.com/lucas-clemente/quic-go v0.21.2-0.20210715202302-4e166bbb8d92
	github.com/pkg/errors v0.9.1
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/net v0.0.0-20210716203947-853a461950ff
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	golang.org/x/tools v0.1.5 // indirect
)

replace github.com/lucas-clemente/quic-go v0.21.2-0.20210715202302-4e166bbb8d92 => github.com/AudriusButkevicius/quic-go v0.7.1-0.20210721142424-a7ba3d6a10a6
