// @generated automatically by Diesel CLI.

diesel::table! {
    block (height) {
        height -> Integer,
        base_target -> BigInt,
        generation_signature -> Text,
        cumulative_difficulty -> Integer,
        generator -> Text,
        creation_time -> Timestamp,
        nonce -> Integer,
        seed -> Text,
        poc_time -> Integer,
    }
}
