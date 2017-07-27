use Cro::Connection;
use Cro::Message;
use Cro::Replyable;
use Cro::Sink;
use Cro::Source;
use Cro::TCP;
use Cro::Types;
use IO::Socket::Async::SSL;

class Cro::SSL::Replier does Cro::Sink {
    has $!socket;
    
    submethod BUILD(:$!socket!) { }
    
    method consumes() { Cro::TCP::Message }

    method sinker(Supply:D $pipeline) returns Supply:D {
        supply {
            whenever $pipeline {
                $!socket.write(.data);
                LAST $!socket.close;
            }
        }
    }
}

class Cro::SSL::ServerConnection does Cro::Connection does Cro::Replyable {
    has $!socket;
    has $.replier;

    method produces() { Cro::TCP::Message }

    submethod BUILD(:$!socket!) {
        $!replier = Cro::SSL::Replier.new(:$!socket)
    }

    method incoming() {
        supply {
            whenever $!socket.Supply(:bin) -> $data {
                emit Cro::TCP::Message.new(:$data);
            }
        }
    }
}

class Cro::SSL::Listener does Cro::Source {
    has Str $.host;
    has Cro::Port $.port;
    has %!ssl-config;

    submethod BUILD(Str :$!host = 'localhost', Cro::Port :$!port!, *%!ssl-config) {}

    method produces() { Cro::SSL::ServerConnection }

    method incoming() {
        supply {
            with %!ssl-config<http> {
                if $_ == <1.1 2> && !IO::Socket::Async::SSL.supports-alpn {
                    die 'HTTP/2 is specified, however ALPN is not supported';
                } elsif $_ == <1.1 2> {
                    %!ssl-config<alpn> = <h2 http/1.1>;
                } elsif $_ == <1.1> {
                    %!ssl-config<alpn> = <http/1.1>;
                }
            }
            without %!ssl-config<http> {
                if IO::Socket::Async::SSL.supports-alpn {
                    %!ssl-config<alpn> = <h2 http/1.1>;
                } else {
                    %!ssl-config<alpn> = <http/1.1>;
                }
            }
            whenever IO::Socket::Async::SSL.listen($!host, $!port, |%!ssl-config) -> $socket {
                emit Cro::SSL::ServerConnection.new(:$socket);
            }
        }
    }
}

class Cro::SSL::Connector does Cro::Connector {
    class Transform does Cro::Transform {
        has $!socket;

        submethod BUILD(IO::Socket::Async::SSL :$!socket!) {}

        method consumes() { Cro::TCP::Message }
        method produces() { Cro::TCP::Message }

        method transformer(Supply $incoming --> Supply) {
            supply {
                whenever $incoming {
                    whenever $!socket.write(.data) {}
                }
                whenever $!socket.Supply(:bin) -> $data {
                    emit Cro::TCP::Message.new(:$data);
                    LAST done;
                }
                CLOSE {
                    $!socket.close;
                }
            }
        }
    }

    method consumes() { Cro::TCP::Message }
    method produces() { Cro::TCP::Message }

    method connect(*%options --> Promise) {
        my $host = %options<host>:delete // 'localhost';
        my $port = %options<port>:delete;
        IO::Socket::Async::SSL.connect($host, $port, |%options)
            .then({ Transform.new(socket => .result) })
    }
}
