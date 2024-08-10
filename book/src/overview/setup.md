# Project Setup

INET integrates itself into the `des` runtime, as a root processing element (called `IOPlugin`).
To avoid the need to add this module on every node, you should override the default processing
elements of all nodes. INET provides a shorthand function to do this:

```rust
fn main() {
    
    /* Build the simulation, run it, eat cookies */
}
```

This function should be called before anything else, since most parts of the INET API
depend on the existence of an instantiated `IOPlugin`. Should a module not contain
this plugin, you will surely encounter an error message in the form:

```
Custom { kind: Other, error: "Missing IOContext"
```

Note that INET uses `std::io::Error` as its error type, to ensure consitency with both
`tokio::net` and `std::net` implementations.

Once INET is initalized every module will be stared with a IOPlugin attached. This plugin will capture
and possibly consume incoming messages, as part usual working of a networking stack. However this
processing element will also ignore messages, clearly not intended for it. A freshly initalized 
IOPlugin will ignore almost all packets, expect:

- Messages with the message kind `KIND_LINK_UPDATE`, that also contain a `LinkUpdate` struct as content
- Messages with the message kind `KIND_IO_TIMEOUT`, independent of content

All other messages will be ignore in the inital configuration of an IO plugin. If you need to send
other messages, ignored by the INET stack, the easiest solution is to avoid these two message kinds.
If that is not possible, you can manually deactivate the IO plugin, by calling `inet::deactivate`

```rust
# use des::prelude::*;
struct MyModule;
impl Module for MyModule {
    # fn new() -> Self { Self }
    fn at_sim_start(&mut self, _: usize) {
        inet::deactivate();
        schedule_in(Message::new().kind(KIND_IO_PLUGIN).build(), SimTime::ZERO);
    }

    fn handle_message(&mut self, msg: Message) {
        assert_eq!(msg.kind(), KIND_IO_PLUGIN);
    }
}
```

