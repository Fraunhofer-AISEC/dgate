using Go = import "/go.capnp";
@0x9e69ec84d6f1f4cd;
$Go.package("main");
$Go.import("main/messages");

struct TimestampMessage {
    repetition @0 :UInt16;
    # The repetition count

    nonce @1 :Data;
    # The nonce belonging to this series
}
