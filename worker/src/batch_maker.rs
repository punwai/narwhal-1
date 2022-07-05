// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{quorum_waiter::QuorumWaiterMessage, worker::WorkerMessage};
use config::{Committee, WorkerId};
use crypto::traits::VerifyingKey;
use network::WorkerNetwork;
#[cfg(feature = "benchmark")]
use std::convert::TryInto as _;
use tokio::{
    sync::{
        mpsc::{Receiver, Sender},
        watch,
    },
    task::JoinHandle,
    time::{sleep, Duration, Instant},
};
#[cfg(feature = "benchmark")]
use tracing::info;
#[cfg(feature = "benchmark")]
use types::serialized_batch_digest;
use types::{Batch, Reconfigure, Transaction};

#[cfg(test)]
#[path = "tests/batch_maker_tests.rs"]
pub mod batch_maker_tests;

/// Assemble clients transactions into batches.
pub struct BatchMaker<PublicKey: VerifyingKey> {
    /// The public key of this authority.
    name: PublicKey,
    /// The id of this worker.
    id: WorkerId,
    /// The committee information.
    committee: Committee<PublicKey>,
    /// The preferred batch size (in bytes).
    batch_size: usize,
    /// The maximum delay after which to seal the batch.
    max_batch_delay: Duration,
    /// Receive reconfiguration updates.
    rx_reconfigure: watch::Receiver<Reconfigure<PublicKey>>,
    /// Channel to receive transactions from the network.
    rx_transaction: Receiver<Transaction>,
    /// Output channel to deliver sealed batches to the `QuorumWaiter`.
    tx_message: Sender<QuorumWaiterMessage<PublicKey>>,
    /// Holds the current batch.
    current_batch: Batch,
    /// Holds the size of the current batch (in bytes).
    current_batch_size: usize,
    /// A network sender to broadcast the batches to the other workers.
    network: WorkerNetwork,
}

impl<PublicKey: VerifyingKey> BatchMaker<PublicKey> {
    pub fn spawn(
        name: PublicKey,
        id: WorkerId,
        committee: Committee<PublicKey>,
        batch_size: usize,
        max_batch_delay: Duration,
        rx_reconfigure: watch::Receiver<Reconfigure<PublicKey>>,
        rx_transaction: Receiver<Transaction>,
        tx_message: Sender<QuorumWaiterMessage<PublicKey>>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            Self {
                name,
                id,
                committee,
                batch_size,
                max_batch_delay,
                rx_reconfigure,
                rx_transaction,
                tx_message,
                current_batch: Batch(Vec::with_capacity(batch_size * 2)),
                current_batch_size: 0,
                network: WorkerNetwork::default(),
            }
            .run()
            .await;
        })
    }

    /// Main loop receiving incoming transactions and creating batches.
    async fn run(&mut self) {
        let timer = sleep(self.max_batch_delay);
        tokio::pin!(timer);

        loop {
            tokio::select! {
                // Assemble client transactions into batches of preset size.
                Some(transaction) = self.rx_transaction.recv() => {
                    self.current_batch_size += transaction.len();
                    self.current_batch.0.push(transaction);
                    if self.current_batch_size >= self.batch_size {
                        self.seal().await;
                        timer.as_mut().reset(Instant::now() + self.max_batch_delay);
                    }
                },

                // If the timer triggers, seal the batch even if it contains few transactions.
                () = &mut timer => {
                    if !self.current_batch.0.is_empty() {
                        self.seal().await;
                    }
                    timer.as_mut().reset(Instant::now() + self.max_batch_delay);
                }

                // Trigger reconfigure.
                result = self.rx_reconfigure.changed() => {
                    result.expect("Committee channel dropped");
                    let message = self.rx_reconfigure.borrow().clone();
                    match message {
                        Reconfigure::NewCommittee(new_committee) => {
                            self.committee=new_committee;
                        },
                        Reconfigure::Shutdown(_token) => return
                    }
                }
            }

            // Give the change to schedule other tasks.
            tokio::task::yield_now().await;
        }
    }

    /// Seal and broadcast the current batch.
    async fn seal(&mut self) {
        #[cfg(feature = "benchmark")]
        let size = self.current_batch_size;

        // Look for sample txs (they all start with 0) and gather their txs id (the next 8 bytes).
        #[cfg(feature = "benchmark")]
        let tx_ids: Vec<_> = self
            .current_batch
            .0
            .iter()
            .filter(|tx| tx[0] == 0u8 && tx.len() > 8)
            .filter_map(|tx| tx[1..9].try_into().ok())
            .collect();

        // Serialize the batch.
        self.current_batch_size = 0;
        let batch: Batch = Batch(self.current_batch.0.drain(..).collect());
        let message = WorkerMessage::<PublicKey>::Batch(batch);
        let serialized = bincode::serialize(&message).expect("Failed to serialize our own batch");

        #[cfg(feature = "benchmark")]
        {
            // NOTE: This is one extra hash that is only needed to print the following log entries.
            if let Ok(digest) = serialized_batch_digest(&serialized) {
                for id in tx_ids {
                    // NOTE: This log entry is used to compute performance.
                    info!(
                        "Batch {:?} contains sample tx {}",
                        digest,
                        u64::from_be_bytes(id)
                    );
                }

                // NOTE: This log entry is used to compute performance.
                info!("Batch {:?} contains {} B", digest, size);
            }
        }

        // Broadcast the batch through the network.
        let workers_addresses: Vec<_> = self
            .committee
            .others_workers(&self.name, &self.id)
            .into_iter()
            .map(|(name, addresses)| (name, addresses.worker_to_worker))
            .collect();
        let (names, addresses): (Vec<_>, _) = workers_addresses.iter().cloned().unzip();
        let handlers = self.network.broadcast(addresses, &message).await;

        // Send the batch through the deliver channel for further processing.
        self.tx_message
            .send(QuorumWaiterMessage {
                batch: serialized,
                handlers: names.into_iter().zip(handlers.into_iter()).collect(),
            })
            .await
            .expect("Failed to deliver batch");
    }
}
