use Crow;
use Crow::SSL;
use Crow::TCP;
use IO::Socket::Async::SSL;
use Test;

constant TEST_PORT = 31315;
constant %ca := { ca-file => 't/certs-and-keys/ca-crt.pem' };
constant %key-cert := {
    private-key-file => 't/certs-and-keys/server-key.pem',
    certificate-file => 't/certs-and-keys/server-crt.pem'
};

# Type relationships.
ok Crow::SSL::Listener ~~ Crow::Source, 'SSL listener is a source';
ok Crow::SSL::Listener.produces ~~ Crow::SSL::Connection, 'SSL listener produces connections';
ok Crow::SSL::Connection ~~ Crow::Connection, 'SSL connection is a connection';
ok Crow::SSL::Connection ~~ Crow::Replyable, 'SSL connection is replyable';
ok Crow::SSL::Connection.produces ~~ Crow::TCP::Message, 'SSL connection produces TCP messages';

# Crow::SSL::Listener
{
    my $lis = Crow::SSL::Listener.new(port => TEST_PORT, |%key-cert);
    is $lis.port, TEST_PORT, 'Listener has correct port';
    dies-ok { await IO::Socket::Async::SSL.connect('localhost', TEST_PORT, |%ca) },
        'Not listening simply by creating the object';

    my $incoming = $lis.incoming;
    ok $incoming ~~ Supply, 'incoming returns a Supply';
    dies-ok { await IO::Socket::Async::SSL.connect('localhost', TEST_PORT, |%ca) },
        'Still not listening as Supply not yet tapped';

    my $server-conns = Channel.new;
    my $tap = $incoming.tap({ $server-conns.send($_) });
    my $client-conn-a;
    lives-ok { $client-conn-a = await IO::Socket::Async::SSL.connect('localhost', TEST_PORT, |%ca) },
        'Listening for connections once the Supply is tapped';
    ok $server-conns.receive ~~ Crow::SSL::Connection,
        'Listener emitted a SSL connection';
    nok $server-conns.poll, 'Only that one connection emitted';
    $client-conn-a.close;

    my $client-conn-b = await IO::Socket::Async::SSL.connect('localhost', TEST_PORT, |%ca);
    ok $server-conns.receive ~~ Crow::SSL::Connection,
        'Listener emitted second connection';
    nok $server-conns.poll, 'Only that one connection emitted';
    $client-conn-b.close;

    $tap.close;
    dies-ok { await IO::Socket::Async::SSL.connect('localhost', TEST_PORT, |%ca) },
        'Not listening after Supply tap closed';
}

# Crow::SSL::Connection and Crow::TCP::Message
{
    my $lis = Crow::SSL::Listener.new(port => TEST_PORT, |%key-cert);
    my $server-conns = Channel.new;
    my $tap = $lis.incoming.tap({ $server-conns.send($_) });
    my $client-conn = await IO::Socket::Async::SSL.connect('localhost', TEST_PORT, |%ca);
    my $client-received = Channel.new;
    $client-conn.Supply(:bin).tap({ $client-received.send($_) });
    my $server-conn = $server-conns.receive;

    my $rec-supply = $server-conn.incoming;
    ok $rec-supply ~~ Supply, 'Connection incoming method returns a Supply';

    my $received = Channel.new;
    $rec-supply.tap({ $received.send($_) });

    $client-conn.write('First packet'.encode('utf-8'));
    my $first-message = $received.receive;
    ok $first-message ~~ Crow::TCP::Message,
        'Received message is a Crow::TCP::Message';
    ok $first-message.data ~~ Blob,
        'Message data is in a Blob';
    is $first-message.data.decode('utf-8'), 'First packet',
        'Message data has correct value';

    $client-conn.write(Blob.new(0xFE, 0xED, 0xBE, 0xEF));
    my $second-message = $received.receive;
    ok $second-message ~~ Crow::TCP::Message,
        'Second received message is a Crow::TCP::Message';
    ok $second-message.data ~~ Blob,
        'Second message data is in a Blob';
    is $second-message.data.list, (0xFE, 0xED, 0xBE, 0xEF),
        'Second message data has correct value';

    my $replier = $server-conn.replier;
    ok $replier ~~ Crow::Sink, 'The SSL connection replier is a Crow::Sink';

    my $fake-replies = Supplier.new;
    my $sinker = $replier.sinker($fake-replies.Supply);
    ok $sinker ~~ Supply, 'Reply sinker returns a Supply';
    lives-ok { $sinker.tap }, 'Can tap that Supply';

    $fake-replies.emit(Crow::TCP::Message.new(data => 'First reply'.encode('utf-8')));
    is $client-received.receive.decode('utf-8'), 'First reply',
        'First TCP::Message reply sent successfully';

    $fake-replies.emit(Crow::TCP::Message.new(data => 'Second reply'.encode('utf-8')));
    is $client-received.receive.decode('utf-8'), 'Second reply',
        'Second TCP::Message reply sent successfully';

    $client-conn.close;
    $tap.close;
}

{
    my class UppercaseTransform does Crow::Transform {
        method consumes() { Crow::TCP::Message }
        method produces() { Crow::TCP::Message }
        method transformer($incoming) {
            supply {
                whenever $incoming -> $message {
                    $message.data = $message.data.decode('latin-1').uc.encode('latin-1');
                    emit $message;
                }
            }
        }
    }

    my $listener = Crow::SSL::Listener.new(port => TEST_PORT, |%key-cert);
    my $loud-service = Crow.compose($listener, UppercaseTransform);
    ok $loud-service ~~ Crow::Service,
        'Crow::SSL::Listener and a transform compose to make a service';
    lives-ok { $loud-service.start }, 'Can start the service';

    my $client-conn-a = await IO::Socket::Async::SSL.connect('localhost', TEST_PORT, |%ca);
    my $client-received-a = Channel.new;
    $client-conn-a.Supply(:bin).tap({ $client-received-a.send($_) });
    $client-conn-a.print("Can you hear me?");
    is $client-received-a.receive.decode('latin-1'), "CAN YOU HEAR ME?",
        'Service processes messages (first connection)';

    my $client-conn-b = await IO::Socket::Async::SSL.connect('localhost', TEST_PORT, |%ca);
    my $client-received-b = Channel.new;
    $client-conn-b.Supply(:bin).tap({ $client-received-b.send($_) });
    $client-conn-b.print("I'm over here!");
    is $client-received-b.receive.decode('latin-1'), "I'M OVER HERE!",
        'Service processes messages (second concurrent connection)';

    $client-conn-a.print("No, not there...");
    is $client-received-a.receive.decode('latin-1'), "NO, NOT THERE...",
        'Further messages on first connection processed';
    $client-conn-a.close;

    $client-conn-b.print("Bah, you suck at this");
    is $client-received-b.receive.decode('latin-1'), "BAH, YOU SUCK AT THIS",
        'Second connection fine after first closed';
    $client-conn-b.close;

    lives-ok { $loud-service.stop }, 'Can stop the service';
    dies-ok { await IO::Socket::Async::SSL.connect('localhost', TEST_PORT, |%ca) },
        'Cannot connect to service after it has been stopped';
}

done-testing;
