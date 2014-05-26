#include <string.h>
#include <string>
#include <functional>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <node.h>
#include <v8.h>

using namespace v8;

namespace {

/*
Handle<Value> Method(const Arguments& args) {
  HandleScope scope;
  return scope.Close(String::New("world"));
}
*/

int parse_addrinfo(const Arguments& args, struct addrinfo **result)
{
  if (args.Length() != 1 || !args[0]->IsObject()) return -1;

  struct addrinfo hints;
  const char *node = 0, *service = 0;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = 0;
  hints.ai_flags    = 0;
  hints.ai_protocol = 0;

  v8::Local<v8::Object> opts      = args[0]->ToObject();
  v8::Local<v8::Value>  node_     = opts->Get(String::NewSymbol("node"));
  v8::Local<v8::Value>  service_  = opts->Get(String::NewSymbol("service"));
  v8::Local<v8::Value>  family_   = opts->Get(String::NewSymbol("family"));
  v8::Local<v8::Value>  socktype_ = opts->Get(String::NewSymbol("socktype"));
  v8::Local<v8::Value>  protocol_ = opts->Get(String::NewSymbol("protocol"));
  v8::Local<v8::Value>  flags_    = opts->Get(String::NewSymbol("flags"));

  v8::String::Utf8Value node_s    (node_    ->ToString());
  v8::String::Utf8Value service_s (service_ ->ToString());
  v8::String::Utf8Value family_s  (family_  ->ToString());
  v8::String::Utf8Value socktype_s(socktype_->ToString());
  
  if(node_->IsString())    node    = *node_s;
  if(service_->IsString()) service = *service_s;
  
  if(!family_->IsString() || *family_s == 0);
  else if(std::string(*family_s) == "AF_INET")   hints.ai_family = AF_INET;
  else if(std::string(*family_s) == "AF_INET6")  hints.ai_family = AF_INET6;
  else if(std::string(*family_s) == "AF_UNSPEC") hints.ai_family = AF_UNSPEC;
  
  if(!socktype_->IsString() || *socktype_s == 0);
  else if(std::string(*socktype_s) == "SOCK_STREAM") hints.ai_socktype = SOCK_STREAM;
  else if(std::string(*socktype_s) == "SOCK_DGRAM")  hints.ai_socktype = SOCK_DGRAM;
  
  if(protocol_->IsNumber()) hints.ai_protocol = protocol_->ToInteger()->Value();
  if(flags_->IsNumber())    hints.ai_flags    = flags_   ->ToInteger()->Value();

  int s = getaddrinfo(node, service, &hints, result);
  
  return s;
}

Handle<Value> Socket(const Arguments& args) {
  HandleScope scope;
  
  if (args.Length() != 1 || !args[0]->IsObject()) {
    ThrowException(Exception::TypeError(String::New("Wrong argument #1, expected {node: 'ip|hostname', service: 'portname', family: 'AF_UNSPEC|AF_INET|AF_INET6', socktype: 'SOCK_STREAM|SOCK_DGRAM', protocol: 0, flags: 0, bind: false}")));
    return scope.Close(Undefined());
  }
  struct addrinfo *result, *rp;
  int fd = -1;
  
  int s = parse_addrinfo(args, &result);

  if(s != 0) {
    ThrowException(Exception::TypeError(String::New(gai_strerror(s))));
    freeaddrinfo(result);
    return scope.Close(Undefined());
  }
  
  for (rp = result; rp != NULL; rp = rp->ai_next) {
  
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

    if(fd == -1){
      continue;
    }
    
    v8::Local<v8::Object> opts  = args[0]->ToObject();
    v8::Local<v8::Value>  bind_ = opts->Get(String::NewSymbol("bind"));

    if(bind_->ToBoolean()->Value()) {    
      if(bind(fd, result->ai_addr, result->ai_addrlen) == -1) {
        close(fd);
        fd = -1;
        continue;
      }
    }
  }
  
  freeaddrinfo(result);
  
  if(fd == -1) {
    ThrowException(Exception::TypeError(String::New(strerror(errno))));
    return scope.Close(Undefined());
  }
  
  return scope.Close(Integer::New(fd));
  /*
  }
  
  
  int domain   = 0;
  int type     = 0;
  int protocol = 0;
  
  if (args.Length() < 2) {
    ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    return scope.Close(Undefined());
  }
  
  v8::String::Utf8Value param_domain(args[0]->ToString());
  
  if     (std::string(*param_domain) == "AF_INET")  domain = AF_INET;
  else if(std::string(*param_domain) == "AF_INET6") domain = AF_INET6;
  else {
    ThrowException(Exception::TypeError(String::New("Wrong argument #1, expected 'AF_INET' or 'AF_INET6' for domain")));
    return scope.Close(Undefined());
  }
  
  v8::String::Utf8Value param_type(args[1]->ToString());
  
  if     (std::string(*param_type) == "SOCK_STREAM") type = SOCK_STREAM;
  else if(std::string(*param_type) == "SOCK_DGRAM")  type = SOCK_DGRAM;
  else {
    ThrowException(Exception::TypeError(String::New("Wrong argument #2, expected 'SOCK_STREAM' or 'SOCK_DGRAM' for type")));
    return scope.Close(Undefined());
  }

  if (args.Length() < 3) {
    protocol = 0;
  } else if(args[2]->IsNumber()) {
    protocol = args[2]->ToInteger()->Value();
  } else {
    ThrowException(Exception::TypeError(String::New("Wrong argument #3, expected integer for protocol")));
    return scope.Close(Undefined());
  }
  
  int sockfd = socket(domain, type, protocol);
  
  return scope.Close(Integer::New(sockfd));
  */
}
/*
Handle<Value> Bind(const Arguments& args) {
  HandleScope scope;
  
  int sockfd = 0;
  int res = 0;
  
  if (args.Length() < 1 || !args[0]->IsNumber()) {
    ThrowException(Exception::TypeError(String::New("Wrong argument #1, expected integer file descriptor")));
    return scope.Close(Undefined());
  } else {
    sockfd = args[0]->ToInteger()->Value();
  }
  
  if (args.Length() < 1 || !args[1]->IsObject()) {
    ThrowException(Exception::TypeError(String::New("Wrong argument #2, expected {family: ...}")));
    return scope.Close(Undefined());
  }
  
  v8::Local<v8::Object> param_addr = args[1]->ToObject();
  v8::String::Utf8Value param_family(param_addr->Get(String::NewSymbol("family"))->ToString());
  int family = 0;
  
  if     (std::string(*param_family) == "AF_INET")  family = AF_INET;
  //else if(std::string(*param_family) == "AF_INET6") family = AF_INET6;
  else {
    ThrowException(Exception::TypeError(String::New("Wrong argument #2, expected family to be 'AF_INET' or 'AF_INET6'")));
    return scope.Close(Undefined());
  }
  
  if(family == AF_INET) {
    v8::Local<v8::Value> param_port = param_addr->Get(String::NewSymbol("port"));
    if(!param_port->IsNumber()) {
      ThrowException(Exception::TypeError(String::New("Wrong argument #2, expected port an integer")));
      return scope.Close(Undefined());
    }
    int port = param_port->ToInteger()->Value();
    
    struct sockaddr_in addr = {AF_INET, htons(port), };
    
    res = bind(sockfd, &addr, sizeof(struct sockaddr_in));
  }
  
  return scope.Close(Integer::New(res));
}
*/
Handle<Value> Close(const Arguments& args) {
  HandleScope scope;
  
  if (args.Length() < 1 || !args[0]->IsNumber()) {
    ThrowException(Exception::TypeError(String::New("Wrong argument #1, expected integer file descriptor")));
    return scope.Close(Undefined());
  }

  int sockfd = args[0]->ToInteger()->Value();
  
  int res = close(sockfd);
  
  return scope.Close(Integer::New(res));
}

void init(Handle<Object> exports) {
  //exports->Set(String::NewSymbol("hello"),  FunctionTemplate::New(Method)->GetFunction());
  exports->Set(String::NewSymbol("socket"), FunctionTemplate::New(Socket)->GetFunction());
  //exports->Set(String::NewSymbol("bind"),   FunctionTemplate::New(Bind)->GetFunction());
  exports->Set(String::NewSymbol("close"),  FunctionTemplate::New(Close)->GetFunction());
}

}

NODE_MODULE(sock, init);
