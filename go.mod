module post

go 1.16

require golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e

require (
	github.com/yahelmanor/post/post-lib v0.0.0
	google.golang.org/protobuf v1.27.1
)

replace github.com/yahelmanor/post/post-lib v0.0.0 => ../post/post-lib
