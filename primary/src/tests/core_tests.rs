// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::common::create_db_stores;
use anemo::{types::PeerInfo, PeerId};
use fastcrypto::traits::KeyPair;
use prometheus::Registry;
use test_utils::{
    certificate, fixture_batch_with_transactions, header, headers, keys, mock_network_key,
    mock_network_pk, pure_committee_from_keys, shared_worker_cache_from_keys, votes,
    PrimaryToPrimaryMockServer,
};
use types::{CertificateDigest, Header, Vote};

#[tokio::test]
async fn process_header() {
    telemetry_subscribers::init_for_testing();

    let mut keys = keys(None);
    let committee = pure_committee_from_keys(&keys);
    let worker_cache = shared_worker_cache_from_keys(&keys);
    let listener_key = keys.pop().unwrap(); // Skip the header' author.
    let kp = keys.pop().unwrap();
    let network_key = mock_network_key(&kp).private().0.to_bytes();
    let name = kp.public().clone();
    let mut signature_service = SignatureService::new(kp);

    let (_tx_reconfigure, rx_reconfigure) =
        watch::channel(ReconfigureNotification::NewEpoch(committee.clone()));
    let (tx_sync_headers, _rx_sync_headers) = test_utils::test_channel!(1);
    let (tx_sync_certificates, _rx_sync_certificates) = test_utils::test_channel!(1);
    let (tx_primary_messages, rx_primary_messages) = test_utils::test_channel!(1);
    let (_tx_headers_loopback, rx_headers_loopback) = test_utils::test_channel!(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = test_utils::test_channel!(1);
    let (_tx_headers, rx_headers) = test_utils::test_channel!(1);
    let (tx_consensus, _rx_consensus) = test_utils::test_channel!(1);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(1);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);

    // Create test stores.
    let (header_store, certificates_store, payload_store) = create_db_stores();

    // Make the vote we expect to receive.
    let expected = Vote::new(&header(), &name, &mut signature_service).await;

    // Spawn a listener to receive the vote.
    let address = committee
        .primary(&header().author)
        .unwrap()
        .primary_to_primary;
    let (mut handle, _network) =
        PrimaryToPrimaryMockServer::spawn(mock_network_key(&listener_key), address.clone());

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name.clone(),
        &committee,
        certificates_store.clone(),
        payload_store,
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
        None,
    );

    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));

    let own_address =
        network::multiaddr_to_address(&committee.primary(&name).unwrap().primary_to_primary)
            .unwrap();
    let network = anemo::Network::bind(own_address)
        .server_name("narwhal")
        .private_key(network_key)
        .start(anemo::Router::new())
        .unwrap();

    let address = network::multiaddr_to_address(&address).unwrap();
    let network_key = mock_network_pk(&header().author);
    let peer_info = PeerInfo {
        peer_id: PeerId(network_key.public().0.to_bytes()),
        affinity: anemo::types::PeerAffinity::High,
        address: vec![address],
    };
    network.known_peers().insert(peer_info);

    // Spawn the core.
    let _core_handle = Core::spawn(
        name,
        committee.clone(),
        worker_cache,
        header_store.clone(),
        certificates_store.clone(),
        synchronizer,
        signature_service,
        rx_consensus_round_updates,
        /* gc_depth */ 50,
        rx_reconfigure,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        metrics.clone(),
        PrimaryNetwork::new(network),
    );

    // Send a header to the core.
    tx_primary_messages
        .send(PrimaryMessage::Header(header()))
        .await
        .unwrap();

    // Ensure the listener correctly received the vote.
    match handle.recv().await.unwrap() {
        PrimaryMessage::Vote(x) => assert_eq!(x, expected),
        x => panic!("Unexpected message: {:?}", x),
    }

    // Ensure the header is correctly stored.
    let stored = header_store.read(header().id).await.unwrap();
    assert_eq!(stored, Some(header()));

    let mut m = HashMap::new();
    m.insert("epoch", "0");
    m.insert("source", "other");
    assert_eq!(
        metrics.headers_processed.get_metric_with(&m).unwrap().get(),
        1
    );
}

#[tokio::test]
async fn process_header_missing_parent() {
    let mut k = keys(None);
    let committee = pure_committee_from_keys(&k);
    let worker_cache = shared_worker_cache_from_keys(&k);
    let kp = k.pop().unwrap();
    let network_key = mock_network_key(&kp).private().0.to_bytes();
    let name = kp.public().clone();
    let signature_service = SignatureService::new(kp);

    let (_, rx_reconfigure) = watch::channel(ReconfigureNotification::NewEpoch(committee.clone()));
    let (tx_sync_headers, _rx_sync_headers) = test_utils::test_channel!(1);
    let (tx_sync_certificates, _rx_sync_certificates) = test_utils::test_channel!(1);
    let (tx_primary_messages, rx_primary_messages) = test_utils::test_channel!(1);
    let (_tx_headers_loopback, rx_headers_loopback) = test_utils::test_channel!(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = test_utils::test_channel!(1);
    let (_tx_headers, rx_headers) = test_utils::test_channel!(1);
    let (tx_consensus, _rx_consensus) = test_utils::test_channel!(1);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(1);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);

    // Create test stores.
    let (header_store, certificates_store, payload_store) = create_db_stores();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name.clone(),
        &committee,
        certificates_store.clone(),
        payload_store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
        None,
    );

    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));

    let own_address =
        network::multiaddr_to_address(&committee.primary(&name).unwrap().primary_to_primary)
            .unwrap();
    let network = anemo::Network::bind(own_address)
        .server_name("narwhal")
        .private_key(network_key)
        .start(anemo::Router::new())
        .unwrap();

    // Spawn the core.
    let _core_handle = Core::spawn(
        name.clone(),
        committee.clone(),
        worker_cache,
        header_store.clone(),
        certificates_store.clone(),
        synchronizer,
        signature_service,
        rx_consensus_round_updates,
        /* gc_depth */ 50,
        rx_reconfigure,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        metrics.clone(),
        PrimaryNetwork::new(network),
    );

    // Send a header to the core.
    let kp = keys(None).pop().unwrap();
    let builder = types::HeaderBuilder::default();
    let header = builder
        .author(name.clone())
        .round(1)
        .epoch(0)
        .parents([CertificateDigest::default()].iter().cloned().collect())
        .with_payload_batch(fixture_batch_with_transactions(10), 0)
        .build(&kp)
        .unwrap();

    let id = header.id;
    tx_primary_messages
        .send(PrimaryMessage::Header(header))
        .await
        .unwrap();

    // Ensure the header is not stored.
    assert!(header_store.read(id).await.unwrap().is_none());
}

#[tokio::test]
async fn process_header_missing_payload() {
    let mut k = keys(None);
    let committee = pure_committee_from_keys(&k);
    let worker_cache = shared_worker_cache_from_keys(&k);
    let kp = k.pop().unwrap();
    let network_key = mock_network_key(&kp).private().0.to_bytes();
    let name = kp.public().clone();
    let signature_service = SignatureService::new(kp);

    let (_, rx_reconfigure) = watch::channel(ReconfigureNotification::NewEpoch(committee.clone()));
    let (tx_sync_headers, _rx_sync_headers) = test_utils::test_channel!(1);
    let (tx_sync_certificates, _rx_sync_certificates) = test_utils::test_channel!(1);
    let (tx_primary_messages, rx_primary_messages) = test_utils::test_channel!(1);
    let (_tx_headers_loopback, rx_headers_loopback) = test_utils::test_channel!(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = test_utils::test_channel!(1);
    let (_tx_headers, rx_headers) = test_utils::test_channel!(1);
    let (tx_consensus, _rx_consensus) = test_utils::test_channel!(1);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(1);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);

    // Create test stores.
    let (header_store, certificates_store, payload_store) = create_db_stores();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name.clone(),
        &committee,
        certificates_store.clone(),
        payload_store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
        None,
    );

    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));

    let own_address =
        network::multiaddr_to_address(&committee.primary(&name).unwrap().primary_to_primary)
            .unwrap();
    let network = anemo::Network::bind(own_address)
        .server_name("narwhal")
        .private_key(network_key)
        .start(anemo::Router::new())
        .unwrap();

    // Spawn the core.
    let _core_handle = Core::spawn(
        name.clone(),
        committee.clone(),
        worker_cache,
        header_store.clone(),
        certificates_store.clone(),
        synchronizer,
        signature_service,
        rx_consensus_round_updates,
        /* gc_depth */ 50,
        rx_reconfigure,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        metrics.clone(),
        PrimaryNetwork::new(network),
    );

    // Send a header that another node has created to the core.
    // We need this header to be another's node, because our own
    // created headers are not checked against having a payload.
    // Just take another keys other than this node's.
    let keys = keys(None);
    let kp = keys.get(1).unwrap();
    let name = kp.public().clone();
    let builder = types::HeaderBuilder::default();
    let header = builder
        .author(name.clone())
        .round(1)
        .epoch(0)
        .parents(
            Certificate::genesis(&committee)
                .iter()
                .map(|x| x.digest())
                .collect(),
        )
        .with_payload_batch(fixture_batch_with_transactions(10), 0)
        .build(kp)
        .unwrap();

    let id = header.id;
    tx_primary_messages
        .send(PrimaryMessage::Header(header))
        .await
        .unwrap();

    // Ensure the header is not stored.
    assert!(header_store.read(id).await.unwrap().is_none());
}

#[tokio::test]
async fn process_votes() {
    let mut k = keys(None);
    let committee = pure_committee_from_keys(&k);
    let worker_cache = shared_worker_cache_from_keys(&k);
    let kp = k.pop().unwrap();
    let network_key = mock_network_key(&kp).private().0.to_bytes();
    let name = kp.public().clone();
    let signature_service = SignatureService::new(kp);

    let (_tx_reconfigure, rx_reconfigure) =
        watch::channel(ReconfigureNotification::NewEpoch(committee.clone()));
    let (tx_sync_headers, _rx_sync_headers) = test_utils::test_channel!(1);
    let (tx_sync_certificates, _rx_sync_certificates) = test_utils::test_channel!(1);
    let (tx_primary_messages, rx_primary_messages) = test_utils::test_channel!(1);
    let (_tx_headers_loopback, rx_headers_loopback) = test_utils::test_channel!(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = test_utils::test_channel!(1);
    let (_tx_headers, rx_headers) = test_utils::test_channel!(1);
    let (tx_consensus, _rx_consensus) = test_utils::test_channel!(1);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(1);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);

    // Create test stores.
    let (header_store, certificates_store, payload_store) = create_db_stores();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name.clone(),
        &committee,
        certificates_store.clone(),
        payload_store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
        None,
    );

    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));
    let own_address =
        network::multiaddr_to_address(&committee.primary(&name).unwrap().primary_to_primary)
            .unwrap();
    let network = anemo::Network::bind(own_address)
        .server_name("narwhal")
        .private_key(network_key)
        .start(anemo::Router::new())
        .unwrap();

    for (_pubkey, addresses, network_pubkey) in committee.others_primaries(&name) {
        let peer_id = PeerId(network_pubkey.0.to_bytes());
        let address = network::multiaddr_to_address(&addresses.primary_to_primary).unwrap();
        let peer_info = PeerInfo {
            peer_id,
            affinity: anemo::types::PeerAffinity::High,
            address: vec![address],
        };
        network.known_peers().insert(peer_info);
    }

    // Spawn the core.
    let _core_handle = Core::spawn(
        name.clone(),
        committee.clone(),
        worker_cache,
        header_store.clone(),
        certificates_store.clone(),
        synchronizer,
        signature_service,
        rx_consensus_round_updates,
        /* gc_depth */ 50,
        rx_reconfigure,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        metrics.clone(),
        PrimaryNetwork::new(network),
    );

    // Make the certificate we expect to receive.
    let expected = certificate(&Header::default());

    // Spawn all listeners to receive our newly formed certificate.
    let mut handles: Vec<_> = k
        .into_iter()
        .map(|kp| {
            let address = committee.primary(kp.public()).unwrap().primary_to_primary;
            PrimaryToPrimaryMockServer::spawn(mock_network_key(&kp), address)
        })
        .collect();

    // Send a votes to the core.
    for vote in votes(&Header::default()) {
        tx_primary_messages
            .send(PrimaryMessage::Vote(vote))
            .await
            .unwrap();
    }

    // Ensure all listeners got the certificate.
    for (handle, _network) in handles.iter_mut() {
        match handle.recv().await.unwrap() {
            PrimaryMessage::Certificate(x) => assert_eq!(x, expected),
            x => panic!("Unexpected message: {:?}", x),
        }
    }

    let mut m = HashMap::new();
    m.insert("epoch", "0");
    assert_eq!(
        metrics
            .certificates_created
            .get_metric_with(&m)
            .unwrap()
            .get(),
        1
    );
}

#[tokio::test]
async fn process_certificates() {
    let mut k = keys(None);
    let committee = pure_committee_from_keys(&k);
    let worker_cache = shared_worker_cache_from_keys(&k);
    let kp = k.pop().unwrap();
    let network_key = mock_network_key(&kp).private().0.to_bytes();
    let name = kp.public().clone();
    let signature_service = SignatureService::new(kp);

    let (_tx_reconfigure, rx_reconfigure) =
        watch::channel(ReconfigureNotification::NewEpoch(committee.clone()));
    let (tx_sync_headers, _rx_sync_headers) = test_utils::test_channel!(1);
    let (tx_sync_certificates, _rx_sync_certificates) = test_utils::test_channel!(1);
    let (tx_primary_messages, rx_primary_messages) = test_utils::test_channel!(3);
    let (_tx_headers_loopback, rx_headers_loopback) = test_utils::test_channel!(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = test_utils::test_channel!(1);
    let (_tx_headers, rx_headers) = test_utils::test_channel!(1);
    let (tx_consensus, mut rx_consensus) = test_utils::test_channel!(3);
    let (tx_parents, mut rx_parents) = test_utils::test_channel!(1);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);

    // Create test stores.
    let (header_store, certificates_store, payload_store) = create_db_stores();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name.clone(),
        &committee,
        certificates_store.clone(),
        payload_store.clone(),
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
        None,
    );

    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));

    let own_address =
        network::multiaddr_to_address(&committee.primary(&name).unwrap().primary_to_primary)
            .unwrap();
    let network = anemo::Network::bind(own_address)
        .server_name("narwhal")
        .private_key(network_key)
        .start(anemo::Router::new())
        .unwrap();
    // Spawn the core.
    let _core_handle = Core::spawn(
        name,
        committee.clone(),
        worker_cache,
        header_store.clone(),
        certificates_store.clone(),
        synchronizer,
        signature_service,
        rx_consensus_round_updates,
        /* gc_depth */ 50,
        rx_reconfigure,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        metrics.clone(),
        PrimaryNetwork::new(network),
    );

    // Send enough certificates to the core.
    let certificates: Vec<_> = headers().iter().take(3).map(certificate).collect();

    for x in certificates.clone() {
        tx_primary_messages
            .send(PrimaryMessage::Certificate(x))
            .await
            .unwrap();
    }

    // Ensure the core sends the parents of the certificates to the proposer.
    //
    // The first messages are the core letting us know about the round of parent certificates
    for _i in 0..3 {
        let received = rx_parents.recv().await.unwrap();
        assert_eq!(received, (vec![], 0, 0));
    }
    // the next message actually contains the parents
    let received = rx_parents.recv().await.unwrap();
    assert_eq!(received, (certificates.clone(), 1, 0));

    // Ensure the core sends the certificates to the consensus.
    for x in certificates.clone() {
        let received = rx_consensus.recv().await.unwrap();
        assert_eq!(received, x);
    }

    // Ensure the certificates are stored.
    for x in &certificates {
        let stored = certificates_store.read(x.digest()).unwrap();
        assert_eq!(stored, Some(x.clone()));
    }

    let mut m = HashMap::new();
    m.insert("epoch", "0");
    m.insert("source", "other");
    assert_eq!(
        metrics
            .certificates_processed
            .get_metric_with(&m)
            .unwrap()
            .get(),
        3
    );
}

#[tokio::test]
async fn shutdown_core() {
    let mut keys = keys(None);
    let committee = pure_committee_from_keys(&keys);
    let worker_cache = shared_worker_cache_from_keys(&keys);
    let _ = keys.pop().unwrap(); // Skip the header' author.
    let kp = keys.pop().unwrap();
    let network_key = mock_network_key(&kp).private().0.to_bytes();
    let name = kp.public().clone();
    let signature_service = SignatureService::new(kp);

    let (tx_reconfigure, rx_reconfigure) =
        watch::channel(ReconfigureNotification::NewEpoch(committee.clone()));
    let (tx_sync_headers, _rx_sync_headers) = test_utils::test_channel!(1);
    let (tx_sync_certificates, _rx_sync_certificates) = test_utils::test_channel!(1);
    let (_tx_primary_messages, rx_primary_messages) = test_utils::test_channel!(1);
    let (_tx_headers_loopback, rx_headers_loopback) = test_utils::test_channel!(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = test_utils::test_channel!(1);
    let (_tx_headers, rx_headers) = test_utils::test_channel!(1);
    let (tx_consensus, _rx_consensus) = test_utils::test_channel!(1);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(1);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);

    // Create test stores.
    let (header_store, certificates_store, payload_store) = create_db_stores();

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name.clone(),
        &committee,
        certificates_store.clone(),
        payload_store,
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
        None,
    );

    let own_address =
        network::multiaddr_to_address(&committee.primary(&name).unwrap().primary_to_primary)
            .unwrap();
    let network = anemo::Network::bind(own_address)
        .server_name("narwhal")
        .private_key(network_key)
        .start(anemo::Router::new())
        .unwrap();

    // Spawn the core.
    let handle = Core::spawn(
        name,
        committee.clone(),
        worker_cache,
        header_store,
        certificates_store,
        synchronizer,
        signature_service,
        rx_consensus_round_updates,
        /* gc_depth */ 50,
        rx_reconfigure,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        Arc::new(PrimaryMetrics::new(&Registry::new())),
        PrimaryNetwork::new(network),
    );

    // Shutdown the core.
    let shutdown = ReconfigureNotification::Shutdown;
    tx_reconfigure.send(shutdown).unwrap();
    assert!(handle.await.is_ok());
}

#[tokio::test]
async fn reconfigure_core() {
    let mut keys_0 = keys(None);
    let committee = pure_committee_from_keys(&keys_0);
    let worker_cache = shared_worker_cache_from_keys(&keys_0);
    let listener_key = keys_0.pop().unwrap(); // Skip the header' author.
    let kp = keys_0.pop().unwrap();
    let network_key = mock_network_key(&kp).private().0.to_bytes();
    let name = kp.public().clone();
    let mut signature_service = SignatureService::new(kp);

    // Make the new committee & worker cache
    let keys_1 = keys(None);
    let mut new_committee = pure_committee_from_keys(&keys_1);
    new_committee.epoch = 1;

    // All the channels to interface with the core.
    let (tx_reconfigure, rx_reconfigure) =
        watch::channel(ReconfigureNotification::NewEpoch(committee.clone()));
    let (tx_sync_headers, _rx_sync_headers) = test_utils::test_channel!(1);
    let (tx_sync_certificates, _rx_sync_certificates) = test_utils::test_channel!(1);
    let (tx_primary_messages, rx_primary_messages) = test_utils::test_channel!(1);
    let (_tx_headers_loopback, rx_headers_loopback) = test_utils::test_channel!(1);
    let (_tx_certificates_loopback, rx_certificates_loopback) = test_utils::test_channel!(1);
    let (_tx_headers, rx_headers) = test_utils::test_channel!(1);
    let (tx_consensus, _rx_consensus) = test_utils::test_channel!(1);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(1);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);

    // Create test stores.
    let (header_store, certificates_store, payload_store) = create_db_stores();

    // Make the vote we expect to receive.
    let header = test_utils::header_with_epoch(&new_committee);
    let expected = Vote::new(&header, &name, &mut signature_service).await;

    // Spawn a listener to receive the vote.
    let address = new_committee
        .primary(&header.author)
        .unwrap()
        .primary_to_primary;
    let (mut handle, _network) =
        PrimaryToPrimaryMockServer::spawn(mock_network_key(&listener_key), address.clone());

    // Make a synchronizer for the core.
    let synchronizer = Synchronizer::new(
        name.clone(),
        &committee,
        certificates_store.clone(),
        payload_store,
        /* tx_header_waiter */ tx_sync_headers,
        /* tx_certificate_waiter */ tx_sync_certificates,
        None,
    );

    let own_address =
        network::multiaddr_to_address(&committee.primary(&name).unwrap().primary_to_primary)
            .unwrap();
    let network = anemo::Network::bind(own_address)
        .server_name("narwhal")
        .private_key(network_key)
        .start(anemo::Router::new())
        .unwrap();
    let address = network::multiaddr_to_address(&address).unwrap();
    let network_key = mock_network_pk(&header.author);
    let peer_info = PeerInfo {
        peer_id: PeerId(network_key.public().0.to_bytes()),
        affinity: anemo::types::PeerAffinity::High,
        address: vec![address],
    };
    network.known_peers().insert(peer_info);

    // Spawn the core.
    let _core_handle = Core::spawn(
        name,
        committee.clone(),
        worker_cache,
        header_store.clone(),
        certificates_store.clone(),
        synchronizer,
        signature_service,
        rx_consensus_round_updates,
        /* gc_depth */ 50,
        rx_reconfigure,
        /* rx_primaries */ rx_primary_messages,
        /* rx_header_waiter */ rx_headers_loopback,
        /* rx_certificate_waiter */ rx_certificates_loopback,
        /* rx_proposer */ rx_headers,
        tx_consensus,
        /* tx_proposer */ tx_parents,
        Arc::new(PrimaryMetrics::new(&Registry::new())),
        PrimaryNetwork::new(network),
    );

    // Change committee
    let message = ReconfigureNotification::NewEpoch(new_committee.clone());
    tx_reconfigure.send(message).unwrap();

    // Send a header to the core.
    let message = PrimaryMessage::Header(header.clone());
    tx_primary_messages.send(message).await.unwrap();

    // Ensure the listener correctly received the vote.
    match handle.recv().await.unwrap() {
        PrimaryMessage::Vote(x) => assert_eq!(x, expected),
        x => panic!("Unexpected message: {:?}", x),
    }

    // Ensure the header is correctly stored.
    let stored = header_store.read(header.id).await.unwrap();
    assert_eq!(stored, Some(header));
}
