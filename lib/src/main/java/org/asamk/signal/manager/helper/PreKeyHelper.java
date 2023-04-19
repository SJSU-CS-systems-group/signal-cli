package org.asamk.signal.manager.helper;

import org.asamk.signal.manager.SignalDependencies;
import org.asamk.signal.manager.config.ServiceConfig;
import org.asamk.signal.manager.storage.SignalAccount;
import org.asamk.signal.manager.storage.Utils;
import org.asamk.signal.manager.util.KeyUtils;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.ecc.Curve;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.signalservice.api.push.ServiceIdType;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class PreKeyHelper {

	private final static Logger logger = LoggerFactory.getLogger(PreKeyHelper.class);

	private final SignalAccount account;
	private final SignalDependencies dependencies;

	public PreKeyHelper(final SignalAccount account, final SignalDependencies dependencies) {
		this.account = account;
		this.dependencies = dependencies;
	}

	public void refreshPreKeysIfNecessary() throws IOException {
		refreshPreKeysIfNecessary(ServiceIdType.ACI);
		refreshPreKeysIfNecessary(ServiceIdType.PNI);
	}

	public void refreshPreKeysIfNecessary(ServiceIdType serviceIdType) throws IOException {
		if (dependencies.getAccountManager().getPreKeysCount(serviceIdType) < ServiceConfig.PREKEY_MINIMUM_COUNT) {
			refreshPreKeys(serviceIdType);
		}
	}

	public void refreshPreKeys() throws IOException {

		refreshPreKeys(ServiceIdType.ACI);
		refreshPreKeys(ServiceIdType.PNI);

	}

	public void refreshPreKeys(ServiceIdType serviceIdType) throws IOException {
		final var identityKeyPair = account.getIdentityKeyPair(serviceIdType);
		if (identityKeyPair == null) {
			return;
		}
		final var accountId = account.getAccountId(serviceIdType);
		if (accountId == null) {
			return;
		}
		try {
			refreshPreKeys(serviceIdType, identityKeyPair);
		} catch (Exception e) {
			logger.warn("Failed to store new pre keys, resetting preKey id offset", e);
			account.resetPreKeyOffsets(serviceIdType);
			refreshPreKeys(serviceIdType, identityKeyPair);
		}
	}

	private void refreshPreKeys(final ServiceIdType serviceIdType, final IdentityKeyPair identityKeyPair)
			throws IOException {
		List<PreKeyRecord> oneTimePreKeys = null;
		SignedPreKeyRecord signedPreKeyRecord = null;

		oneTimePreKeys = generatePreKeys(serviceIdType);
		signedPreKeyRecord = generateSignedPreKey(serviceIdType, identityKeyPair);
		dependencies.getAccountManager().setPreKeys(serviceIdType, identityKeyPair.getPublicKey(), signedPreKeyRecord,
				oneTimePreKeys);
	}

	private List<PreKeyRecord> dddGeneratePreKeyRecords(String filePath, ServiceIdType serviceIdType) {
		List<PreKeyRecord> records = new ArrayList<>();

		if (filePath != null) {
			ObjectMapper mapper = Utils.createStorageObjectMapper();
			try {
				JsonNode rootNode = mapper.readTree(new File(filePath));
				String preKeysKey = "preKeys";
				if (serviceIdType == ServiceIdType.PNI)
					preKeysKey = "pniPreKeys";
				if (rootNode.hasNonNull(preKeysKey) && rootNode.get(preKeysKey).size() > 0) {
					JsonNode preKeysNode = rootNode.get(preKeysKey);
					for (int i = 0; i < preKeysNode.size(); i++) {
						JsonNode prekey = rootNode.get(preKeysKey).get(i);
						int id = prekey.get("preKeyId").asInt();
						final var publicKeyBytes = Base64.getDecoder().decode(prekey.get("preKeyPublicKey").asText());
						final var privateKeyBytes = Base64.getDecoder()
								.decode(prekey.get("preKeyPrivateKey").asText());

						final var publicKey = Curve.decodePoint(publicKeyBytes, 0);
						final var privateKey = Curve.decodePrivatePoint(privateKeyBytes);

						records.add(new PreKeyRecord(id, new ECKeyPair(publicKey, privateKey)));
					}

				}
			} catch (Exception e) {
				e.printStackTrace();
				System.out.println("Error while handling prekeys from DDD Config");
			}
		} else {
			System.out.println("DDD config not found");
		}

		return records;
	}

	private List<PreKeyRecord> generatePreKeys(ServiceIdType serviceIdType) {
		final var offset = account.getPreKeyIdOffset(serviceIdType);
		List<PreKeyRecord> records;
		if (account.isDisconnected()) {
			records = dddGeneratePreKeyRecords(account.getDDDConfigFile(), serviceIdType);
		} else {
			records = KeyUtils.generatePreKeyRecords(offset, ServiceConfig.PREKEY_BATCH_SIZE);
		}

		account.addPreKeys(serviceIdType, records);

		return records;
	}

	private SignedPreKeyRecord generateSignedPreKey(ServiceIdType serviceIdType, IdentityKeyPair identityKeyPair) {
		final var signedPreKeyId = account.getNextSignedPreKeyId(serviceIdType);
		SignedPreKeyRecord record = null;
		if (account.isDisconnected()) {
			record = dddGenerateSignedPreKey(account.getDDDConfigFile(), serviceIdType);
		} else {
			record = KeyUtils.generateSignedPreKeyRecord(identityKeyPair, signedPreKeyId);
		}
		account.addSignedPreKey(serviceIdType, record);

		return record;
	}

	private SignedPreKeyRecord dddGenerateSignedPreKey(String filePath, ServiceIdType serviceIdType) {
		SignedPreKeyRecord record = null;

		if (filePath != null) {
			ObjectMapper mapper = Utils.createStorageObjectMapper();
			try {
				JsonNode rootNode = mapper.readTree(new File(filePath));
				if (serviceIdType == ServiceIdType.PNI) {
					if (rootNode.hasNonNull("pniSignedPreKeyId") && rootNode.hasNonNull("pniSignedPreKeySignature")
							&& rootNode.hasNonNull("pniSignedPreKeyTimestamp")
							&& rootNode.hasNonNull("pniSignedPreKeyPublicKey")) {
						final var publicKeyBytes = Base64.getDecoder()
								.decode(rootNode.get("pniSignedPreKeyPublicKey").asText());
						final var privateKeyBytes = Base64.getDecoder()
								.decode(rootNode.get("pniSignedPreKeyPrivateKey").asText());

						final var publicKey = Curve.decodePoint(publicKeyBytes, 0);
						final var privateKey = Curve.decodePrivatePoint(privateKeyBytes);

						record = new SignedPreKeyRecord(rootNode.get("pniSignedPreKeyId").asInt(),
								rootNode.get("pniSignedPreKeyTimestamp").asLong(), new ECKeyPair(publicKey, privateKey),
								Base64.getDecoder().decode(rootNode.get("pniSignedPreKeySignature").asText()));
					} else {
						System.out.println("Not all parameters of PNI Signed Key Present");
					}
				} else {
					if (rootNode.hasNonNull("aciSignedPreKeyId") && rootNode.hasNonNull("aciSignedPreKeySignature")
							&& rootNode.hasNonNull("aciSignedPreKeyTimestamp")
							&& rootNode.hasNonNull("aciSignedPreKeyPublicKey")) {
						final var publicKeyBytes = Base64.getDecoder()
								.decode(rootNode.get("aciSignedPreKeyPublicKey").asText());
						final var privateKeyBytes = Base64.getDecoder()
								.decode(rootNode.get("aciSignedPreKeyPrivateKey").asText());

						final var publicKey = Curve.decodePoint(publicKeyBytes, 0);
						final var privateKey = Curve.decodePrivatePoint(privateKeyBytes);

						record = new SignedPreKeyRecord(rootNode.get("aciSignedPreKeyId").asInt(),
								rootNode.get("aciSignedPreKeyTimestamp").asLong(), new ECKeyPair(publicKey, privateKey),
								Base64.getDecoder().decode(rootNode.get("aciSignedPreKeySignature").asText()));
					} else {
						System.out.println("Not all parameters of ACI Signed Key Present");
					}
				}
			} catch (Exception e) {
				System.out.println("Error while handling prekeys from DDD Config");
			}
		} else {
			System.out.println("DDD config not found");
		}

		return record;
	}
}
