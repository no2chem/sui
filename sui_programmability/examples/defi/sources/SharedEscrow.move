/// An escrow for atomic swap of objects without a trusted third party
module DeFi::SharedEscrow {
    use Std::Option::{Self, Option};

    use Sui::ID::{Self, ID, VersionedID};
    use Sui::Transfer;
    use Sui::TxContext::{Self, TxContext};

    /// An object held in escrow
    struct EscrowedObj<T: key + store, phantom ExchangeForT: key + store> has key, store {
        id: VersionedID,
        /// owner of the escrowed object
        sender: address,
        /// intended recipient of the escrowed object
        recipient: address,
        /// ID of the object `sender` wants in exchange
        exchange_for: ID,
        /// the escrowed object
        escrowed: Option<T>,
    }

    // Error codes
    /// An attempt to cancel escrow by a different user than the owner
    const EWRONG_OWNER: u64 = 0;
    /// Exchange by a different user than the `recipient` of the escrowed object
    const EWRONG_RECIPIENT: u64 = 1;
    /// Exchange with a different item than the `exchange_for` field
    const EWRONG_EXCHANGE_OBJECT: u64 = 2;

    /// Create an escrow for exchanging goods with `counterparty`
    public fun create<T: key + store, ExchangeForT: key + store>(
        recipient: address,
        exchange_for: ID,
        escrowed_item: T,
        ctx: &mut TxContext
    ) {
        let sender = TxContext::sender(ctx);
        let id = TxContext::new_id(ctx);
        let escrowed = Option::some(escrowed_item);
        Transfer::share_object(
            EscrowedObj<T,ExchangeForT> {
                id, sender, recipient, exchange_for, escrowed
            }
        );
    }

    /// The `recipient` of the escrow can exchange `obj` with the escrowed item
    public fun exchange<T: key + store, ExchangeForT: key + store>(
        obj: ExchangeForT,
        escrow: &mut EscrowedObj<T, ExchangeForT>,
        ctx: &mut TxContext
    ) {
        let escrowed_item = Option::extract<T>(&mut escrow.escrowed);
        assert!(&TxContext::sender(ctx) == &escrow.recipient, EWRONG_RECIPIENT);
        assert!(ID::id(&obj) == &escrow.exchange_for, EWRONG_EXCHANGE_OBJECT);
        // everything matches. do the swap!
        Transfer::transfer(escrowed_item, TxContext::sender(ctx));
        Transfer::transfer(obj, escrow.sender);
    }

    /// The `sender` can cancel the escrow and get back the escrowed item
    public fun cancel<T: key + store, ExchangeForT: key + store>(
        escrow: &mut EscrowedObj<T, ExchangeForT>,
        ctx: &mut TxContext
    ) {
        assert!(&TxContext::sender(ctx) == &escrow.sender, EWRONG_OWNER);
        Transfer::transfer(Option::extract<T>(&mut escrow.escrowed), escrow.sender);
    }
}
