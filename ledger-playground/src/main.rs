use ledger_apdu::{APDUCommand, };
use ledger::{withLedgersSelect, TransportNativeHID};

fn main() {
    let apdu = APDUCommand {
        cla: 0x80,
        ins: 0x01,
        p1: 0x00,
        p2: 0x00,
        data: vec![0x00, 0x01, 14],
    };
    let always_true_closure = create_ledger_filter("123".to_string()); 
    withLedgersSelect(always_true_closure, |ledger| {
        println!("{}", apdu);
    });
}

fn create_ledger_filter(id: String) -> fn(&mut TransportNativeHID)->bool {
    return |ledger| {
        // TODO: Actually write to ledger and get its ID
        return true;
    };
}
