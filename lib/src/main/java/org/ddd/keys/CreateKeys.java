package org.ddd.keys;

import java.io.IOException;
import org.signal.libsignal.protocol.InvalidKeyException;

public class CreateKeys {
	public static void main(String[] args) throws IOException, InvalidKeyException {

		DDDKeys dddKeys = new DDDKeys();
		dddKeys.generatePublicKeysJsonFile("/Users/spartan/Documents/DDD/keys/publickeys.json");
		dddKeys.generatePublicKeysJsonFile("/Users/spartan/Documents/DDD/keys/privatekeys.json");
		System.out.println("DONE");

	}
}
