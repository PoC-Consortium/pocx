// Copyright (c) 2025 Proof of Capacity Consortium
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::cache::Cache;
use crate::config::PoCXConfig;
use crate::mining_info::*;
use crate::models::Block;
use crate::schema::*;
use bytesize::ByteSize;
use chrono::prelude::*;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::result::Error as DatabaseError;
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

fn genesis_base_target(genesis_blocktime: u64) -> u64 {
    // Genesis base target calculation for 1 TiB starting network capacity
    //
    // Formula: 2^42 / block_time_seconds
    //
    // Derivation:
    // - Each nonce represents 256 KiB (64 bytes * 4096 scoops)
    // - 1 TiB = 2^22 nonces
    // - Expected minimum quality for n nonces ≈ 2^64 / n
    // - For 1 TiB: E(quality) = 2^64 / 2^22 = 2^42
    // - quality_adjusted = quality / base_target
    // - For target block time: base_target = E(quality) / block_time
    // - Therefore: base_target = 2^42 / block_time
    2u64.pow(42) / genesis_blocktime
}

#[derive(Clone)]
pub struct DB {
    conn_pool: Pool<ConnectionManager<SqliteConnection>>,
    cache: Cache,
    config: Arc<PoCXConfig>,
}

impl fmt::Debug for DB {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DB {{ cache: {:?}, config: {:?} }}",
            self.cache, self.config
        )
    }
}
type DatabaseConnection =
    r2d2::PooledConnection<diesel::r2d2::ConnectionManager<diesel::sqlite::SqliteConnection>>;

impl DB {
    /// Creates a new database instance with automatic migrations and genesis
    /// block creation.
    ///
    /// # Arguments
    /// * `dsn` - Database connection string (SQLite file path)
    /// * `config` - Shared configuration for blockchain parameters
    ///
    /// # Returns
    /// Initialized DB instance with connection pool and mining info
    pub fn new(dsn: &str, config: Arc<PoCXConfig>) -> DB {
        let manager = ConnectionManager::<SqliteConnection>::new(dsn);
        let conn_pool = r2d2::Pool::builder()
            .build(manager)
            .expect("failed to create pool");
        let mut conn = conn_pool.get().expect("get connection");

        // Run database migrations to ensure tables exist
        conn.run_pending_migrations(MIGRATIONS)
            .expect("Failed to run database migrations - this is a critical initialization error");

        let latest_block = DB::get_latest_block_init(&mut conn);
        let block_time = config.network.block_time_seconds;
        let mining_info = match latest_block {
            Some(block) => match MiningInfo::from_block(
                block,
                config.network.minimum_compression_level,
                config.network.target_compression_level,
            ) {
                Ok(info) => info,
                Err(e) => {
                    panic!("Failed to create initial mining info from block: {}", e);
                }
            },
            None => {
                // create genesis block
                let forge_time = Utc::now().naive_utc();
                let mining_info = MiningInfo::new(
                    0,
                    genesis_base_target(block_time),
                    Some(config.network.genesis_signature.clone()),
                    config.network.minimum_compression_level,
                    config.network.target_compression_level,
                );
                let genesis_block = Block {
                    height: mining_info.height as i32,
                    base_target: mining_info.base_target as i64,
                    generation_signature: mining_info.generation_signature.clone(),
                    generator: "".to_owned(),
                    creation_time: forge_time,
                    cumulative_difficulty: 0,
                    seed: "".to_owned(),
                    nonce: 0,
                    poc_time: block_time as i32,
                };

                // Ensure genesis block creation succeeds
                diesel::insert_into(block::table)
                    .values(&genesis_block)
                    .execute(&mut conn)
                    .expect(
                        "Failed to create genesis block - this is a critical initialization error",
                    );
                println!("Created genesis block at height 0");
                mining_info
            }
        };
        DB {
            conn_pool,
            cache: Cache::new(mining_info),
            config,
        }
    }

    #[inline]
    fn get_conn(&self) -> DatabaseConnection {
        self.conn_pool.get().expect("get connection")
    }

    fn get_latest_block_init(conn: &mut DatabaseConnection) -> Option<Block> {
        let res = block::table
            .order(block::height.desc())
            .limit(1)
            .get_result(conn);
        match res {
            Ok(block) => Some(block),
            Err(DatabaseError::NotFound) => None,
            Err(e) => {
                eprintln!("Can't get latest block: {}", e);
                None
            }
        }
    }

    /// Retrieves the most recent block from the blockchain.
    ///
    /// # Returns
    /// `Some(Block)` if found, `None` if database is empty or error occurred
    pub fn get_latest_block(&self) -> Option<Block> {
        let res = block::table
            .order(block::height.desc())
            .limit(1)
            .get_result(&mut self.get_conn());
        match res {
            Ok(block) => Some(block),
            Err(DatabaseError::NotFound) => None,
            Err(e) => {
                eprintln!("Can't get latest block: {}", e);
                None
            }
        }
    }

    pub fn create_block(conn: &mut DatabaseConnection, block: Block) {
        let res = diesel::insert_into(block::table)
            .values(&block)
            .execute(conn);
        if let Err(e) = res {
            eprintln!("Can't create block {:?}: {}", block, e);
        }
    }

    pub fn get_elapsed_time(&self, limit: i64) -> Option<(Duration, u64)> {
        let query = block::table
            .select(block::creation_time)
            .order(block::height.desc())
            .limit(limit)
            .get_results::<NaiveDateTime>(&mut self.get_conn());
        match query {
            Ok(query) => {
                if let Some(last_time) = query.last() {
                    match Utc::now()
                        .naive_utc()
                        .signed_duration_since(*last_time)
                        .to_std()
                    {
                        Ok(duration) => Some((duration, query.len() as u64)),
                        Err(e) => {
                            eprintln!("Duration conversion failed: {}", e);
                            None
                        }
                    }
                } else {
                    eprintln!("No blocks found in elapsed time query");
                    None
                }
            }
            Err(e) => {
                eprintln!("Can't calculate elapsed time: {}", e);
                None
            }
        }
    }

    pub fn forge_block(
        &self,
        height: u64,
        generator: String,
        seed: String,
        nonce: u64,
        poc_time: u64,
    ) {
        let forge_time = Utc::now().naive_utc();
        let mut mining_info = self
            .cache
            .mining_info
            .lock()
            .expect("Mining info mutex poisoned");

        // check for a race
        if mining_info.height != height {
            println!("wrong_height");
            return;
        }

        let (address_payload, network_id) = match pocx_address::decode_address(&generator) {
            Ok((payload, net_id)) => (payload, net_id),
            Err(_) => {
                println!("Invalid PoC address!");
                return;
            }
        };

        if network_id != self.config.network.network_id {
            println!(
                "Wrong network ID: expected {:?}, got {:?}",
                self.config.network.network_id, network_id
            );
            return;
        }

        // Remove unused base58_bytes variable - we'll use address_payload directly

        let new_height = mining_info.height + 1;

        // get timespan of last blocks
        let lookback_blocks = self.config.network.difficulty_adjustment.lookback_blocks;
        let (elapsed, blocks) = match self.get_elapsed_time(lookback_blocks) {
            Some(result) => result,
            None => {
                eprintln!("Failed to get elapsed time for difficulty adjustment");
                return;
            }
        };
        // Difficulty adjustment uses current mining info base target
        let scan_time = Duration::from_millis(0); // No fixed scan time offset
        let elapsed = elapsed - scan_time;

        let block_time = self.config.network.block_time_seconds;

        let raw_new_base_target =
            mining_info.base_target * elapsed.as_secs() / (blocks * block_time);

        let new_base_target = raw_new_base_target;
        // Apply configured adjustment limits
        let min_ratio = self
            .config
            .network
            .difficulty_adjustment
            .min_adjustment_ratio;
        let max_ratio = self
            .config
            .network
            .difficulty_adjustment
            .max_adjustment_ratio;
        let new_base_target = u64::max(
            new_base_target,
            (mining_info.base_target as f64 * min_ratio) as u64,
        );
        let new_base_target = u64::min(
            new_base_target,
            (mining_info.base_target as f64 * max_ratio) as u64,
        );
        // Never exceed genesis base target (acts as maximum)
        let max_base_target = genesis_base_target(block_time);
        let new_base_target = u64::min(new_base_target, max_base_target);
        let new_base_target = u64::max(new_base_target, 1);

        // this is just a mining simulation
        let mut dummy_public_key = [0u8; 64];
        dummy_public_key[0..20].copy_from_slice(&address_payload);

        let new_generation_signature = pocx_hashlib::calculate_next_generation_signature(
            &mining_info.generation_signature_bytes,
            &dummy_public_key,
        );

        let new_mining_info = MiningInfo::new(
            new_height,
            new_base_target,
            Some(hex::encode(new_generation_signature)),
            self.config.network.minimum_compression_level,
            self.config.network.target_compression_level,
        );

        DB::create_block(
            &mut self.get_conn(),
            Block {
                height: new_height as i32,
                base_target: new_base_target as i64,
                generation_signature: hex::encode(new_generation_signature),
                generator,
                creation_time: forge_time,
                cumulative_difficulty: 0,
                seed,
                nonce: nonce as i32,
                poc_time: poc_time as i32,
            },
        );
        *mining_info = new_mining_info;
        let network_capacity = calculate_network_capacity(new_base_target, block_time);
        println!(
            "new block: height={}, gensig=...{}, base_target={}, network_capacity={}",
            new_height,
            hex::encode(new_generation_signature)
                .chars()
                .skip(56)
                .take(8)
                .collect::<String>(),
            new_base_target,
            network_capacity
        );
    }

    pub fn get_mining_info(&self) -> MiningInfo {
        self.cache
            .mining_info
            .lock()
            .expect("Mining info mutex poisoned")
            .clone()
    }
}

pub fn quality_adj_to_time(quality: u64, block_time: u64) -> u64 {
    2 * block_time
        - (2.0 * block_time as f64 * (-(quality as f64) / block_time as f64).exp()) as u64
}

/// Calculate estimated network capacity from base target and block time
pub fn calculate_network_capacity(base_target: u64, block_time: u64) -> String {
    // Genesis base target = 2^42 / block_time for 1 TiB
    // Network capacity = genesis_base_target / current_base_target TiB
    // In bytes: capacity = (2^42 / block_time) / base_target * 2^40 bytes
    let genesis_base_target = genesis_base_target(block_time);
    let capacity_ratio = genesis_base_target as f64 / base_target as f64;
    let capacity_bytes = capacity_ratio * (1u64 << 40) as f64; // 1 TiB in bytes
    ByteSize::b(capacity_bytes as u64).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PoCXConfig;
    use std::sync::Arc;

    #[test]
    fn test_db_creation() {
        // Test that DB struct can be created
        let config = Arc::new(PoCXConfig::default());
        let db = DB::new("test_database.db", config);

        // Verify the database components exist - Pool doesn't have is_some/is_none
        // Just check that the pool field exists by accessing it
        let _ = &db.conn_pool;

        // Check that cache is initialized
        let mining_info = db
            .cache
            .mining_info
            .lock()
            .expect("Mining info mutex poisoned in test");
        // Height is u64, so it's always >= 0 by definition
        assert_eq!(mining_info.height, 0);
    }

    #[test]
    fn test_quality_adj_to_time_calculation() {
        // Test quality adjustment to time calculation
        let block_time = 120u64; // Use default config value
        let quality = 1000u64;
        let time_result = quality_adj_to_time(quality, block_time);

        // Should return a reasonable time value
        assert!(time_result > 0);
        assert!(time_result < u64::MAX / 2); // Sanity check

        // Test with zero quality - this actually returns 0 due to the calculation
        let zero_time = quality_adj_to_time(0, block_time);
        assert_eq!(zero_time, 0); // When quality=0, exp(0)=1, so 2*VAR - 2*VAR*1 = 0

        // Test with large quality
        let large_quality = 1000000u64;
        let large_time = quality_adj_to_time(large_quality, block_time);
        assert!(large_time > 0);
    }

    #[test]
    fn test_mining_info_conversion() {
        // Create a test block
        let test_block = Block {
            height: 1000,
            base_target: 50000,
            generation_signature:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            cumulative_difficulty: 75000,
            generator: "test_generator".to_string(),
            creation_time: DateTime::from_timestamp(1234567890, 0).unwrap().naive_utc(),
            nonce: 12345,
            seed: "test_seed".to_string(),
            poc_time: 240,
        };

        // Test MiningInfo creation from block
        let mining_info = MiningInfo::from_block(test_block, 1, 4)
            .expect("Test block should create valid mining info");

        assert_eq!(mining_info.height, 1000);
        assert_eq!(mining_info.base_target, 50000);
        assert_eq!(
            mining_info.generation_signature,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(mining_info.target_quality, u64::MAX);
    }

    #[test]
    fn test_block_time_config() {
        // Test that block time from config is reasonable
        let config = PoCXConfig::default();
        assert_eq!(config.network.block_time_seconds, 120); // 2 minutes default

        // Verify it's a reasonable value
        assert!(config.network.block_time_seconds > 0);
        assert!(config.network.block_time_seconds < 3600); // Less than 1 hour
    }

    #[test]
    fn test_block_struct_creation() {
        // Test creating a Block struct with various values
        let block = Block {
            height: 500,
            base_target: 25000,
            generation_signature: "test_signature".to_string(),
            cumulative_difficulty: 100000,
            generator: "test_generator_2".to_string(),
            creation_time: DateTime::from_timestamp(1700000000, 0).unwrap().naive_utc(),
            nonce: 9999,
            seed: "test_seed_2".to_string(),
            poc_time: 180,
        };

        assert_eq!(block.height, 500);
        assert_eq!(block.base_target, 25000);
        assert_eq!(block.generation_signature, "test_signature");
        assert_eq!(block.cumulative_difficulty, 100000);
        assert_eq!(block.generator, "test_generator_2");
        assert_eq!(block.nonce, 9999);
        assert_eq!(block.seed, "test_seed_2");
        assert_eq!(block.poc_time, 180);
    }

    #[test]
    fn test_mathematical_functions() {
        // Test the exponential calculation in quality_adj_to_time
        let quality = 500u64;
        let block_time = 120u64; // Use default config value
        let block_time_f = block_time as f64;

        // Test the exponential component
        let exp_component = (-(quality as f64) / block_time_f).exp();
        assert!(exp_component > 0.0);
        assert!(exp_component <= 1.0); // e^(-x) where x >= 0 should be <= 1

        // Test the full calculation
        let full_calculation = 2.0 * block_time_f * (1.0 - exp_component);
        assert!(full_calculation >= 0.0);
        assert!(full_calculation < 2.0 * block_time_f);
    }

    #[test]
    fn test_edge_case_qualities() {
        // Test edge cases for quality calculation
        let block_time = 120u64; // Use default config value
        let test_cases = [0u64, 1u64, 100u64, 1000u64, 10000u64, u64::MAX / 1000];

        for quality in &test_cases {
            let time_result = quality_adj_to_time(*quality, block_time);

            // Results should be valid and reasonable
            if *quality == 0 {
                assert_eq!(time_result, 0); // Special case: quality 0 gives
                                            // time 0
            } else {
                assert!(time_result > 0);
            }
            assert!(time_result <= 2 * block_time); // Should be less than or
                                                    // equal to max possible
        }
    }

    #[test]
    fn test_duration_handling() {
        // Test Duration creation and handling
        use std::time::Duration;

        let duration = Duration::from_secs(300); // 5 minutes
        assert_eq!(duration.as_secs(), 300);

        let duration_millis = Duration::from_millis(300000); // 5 minutes in millis
        assert_eq!(duration_millis.as_secs(), 300);

        // Test that Duration can handle large values
        let large_duration = Duration::from_secs(86400); // 24 hours
        assert_eq!(large_duration.as_secs(), 86400);
    }

    #[test]
    fn test_network_capacity_calculation() {
        let block_time = 120u64;
        let genesis_base_target = genesis_base_target(block_time);

        // Test with genesis base target (should be 1.0 TiB with bytesize 2.0)
        let capacity_genesis = calculate_network_capacity(genesis_base_target, block_time);
        assert!(capacity_genesis.contains("1") && capacity_genesis.contains("TiB"));

        // Test with half genesis base target (should be 2.0 TiB)
        let capacity_double = calculate_network_capacity(genesis_base_target / 2, block_time);
        assert!(capacity_double.contains("2") && capacity_double.contains("TiB"));

        // Test with double genesis base target (should be 512.0 GiB)
        let capacity_half = calculate_network_capacity(genesis_base_target * 2, block_time);
        assert!(capacity_half.contains("512") && capacity_half.contains("GiB"));
    }
}
