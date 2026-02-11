// @generated automatically by Diesel CLI.

diesel::table! {
    submissions (id) {
        id -> Integer,
        account_id -> Text,
        machine_id -> Text,
        height -> BigInt,
        raw_quality -> BigInt,
        timestamp -> Timestamp,
    }
}
