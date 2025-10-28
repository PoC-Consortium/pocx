// @generated automatically by Diesel CLI.

diesel::table! {
    submissions (id) {
        id -> Integer,
        account_id -> Text,
        machine_id -> Text,
        height -> BigInt,
        quality -> BigInt,
        base_target -> BigInt,
        timestamp -> Timestamp,
    }
}
