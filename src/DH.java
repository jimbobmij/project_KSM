import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import matrix.generator.ModMatGen;

public class DH {
	public static void main(String[] args) {
		try {
			Keysize.measureTime();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}

class Keysize {
	public static void measureTime() throws IOException {
		String OUTPUT = "resultDH2.csv";
		int NUM_RUN = 100;
		int NUM_CONDITION = 10;

		PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(OUTPUT)));
		printHeader(pw);

		for (int i = 0; i < NUM_CONDITION; i++) {
			int keysize = 512 * (i + 1);
			System.out.println("keysize:" + keysize);

			for (int j = 0; j < NUM_RUN; j++) {

				try {
					printResurt(pw, keysize, runMyWay(keysize,j));
				} catch (InvalidKeyException | NoSuchAlgorithmException e) {
					e.printStackTrace();
				}

			}
		}
		pw.flush();
		pw.close();
		System.out.println("End");
	}

	static String DH = "DH";

	private static long[] run(int keysize) throws NoSuchAlgorithmException, InvalidKeyException {
		long[] time = new long[5];
		KeyPairGenerator keyGen;
		KeyAgreement keyAgr;

		// Bob's makes key pair.
		time[0] = System.currentTimeMillis();
		keyGen = KeyPairGenerator.getInstance(DH);
		keyGen.initialize(keysize);
		KeyPair BobKeyPair = keyGen.generateKeyPair();
		// Bob sends his public key to Alice.
		PublicKey BobPubKey = BobKeyPair.getPublic();

		// Alice makes her key pair.
		time[1] = System.currentTimeMillis();
		keyGen = KeyPairGenerator.getInstance(DH);
		keyGen.initialize(keysize);
		KeyPair AliceKeyPair = keyGen.generateKeyPair();
		// Alice sends his public key to Bob.
		PublicKey AlicePubKey = AliceKeyPair.getPublic();

		// Alice calculates SSK.
		time[2] = System.currentTimeMillis();
		keyAgr = KeyAgreement.getInstance(DH);
		keyAgr.init(AliceKeyPair.getPrivate());
		keyAgr.doPhase(BobPubKey, true);
		byte[] ASK = keyAgr.generateSecret();

		// Bob calculates SSK.
		time[3] = System.currentTimeMillis();
		keyAgr = KeyAgreement.getInstance(DH);
		keyAgr.init(BobKeyPair.getPrivate());
		keyAgr.doPhase(AlicePubKey, true);
		byte[] BSK = keyAgr.generateSecret();

		time[4] = System.currentTimeMillis();

		printKeyParams(AlicePubKey);

		if (!Arrays.equals(ASK, BSK))
			throw new RuntimeException("Keys are not equals.");
		return time;
	}

	private static long[] runMyWay(int keysize, int count) throws NoSuchAlgorithmException, InvalidKeyException {
		long[] time = new long[5];

		Random random = new SecureRandom();

		BigInteger p = BigInteger.probablePrime(keysize, random);
		BigInteger g = ModMatGen.randomBInt(random, p);
		//BigInteger g = new BigInteger("2147483647");

		long begin = System.currentTimeMillis();

		time[0] = System.currentTimeMillis();
		BigInteger xB = ModMatGen.randomBInt(random, p);
		BigInteger yB = g.modPow(xB, p);

		time[1] = System.currentTimeMillis();
		BigInteger xA = ModMatGen.randomBInt(random, p);
		BigInteger yA = g.modPow(xA, p);

		time[2] = System.currentTimeMillis();
		BigInteger ASK = yB.modPow(xA, p);

		time[3] = System.currentTimeMillis();
		BigInteger BSK = yA.modPow(xB, p);

		time[4] = System.currentTimeMillis();

		long end = System.currentTimeMillis();
		System.out.println(count + "th TRIAL" + "[" + keysize + " bits]:" + (end - begin));


		if (!ASK.equals(BSK))
			throw new RuntimeException("Keys are not equals.");
		return time;
	}

	private static void printHeader(PrintWriter pw) {
		String[] label = { "size", "MKP", "SKP", "SSK", "MSK", "Total" };
		String str = "";
		for (int i = 0; i < label.length - 1; i++)
			str += label[i] + ", ";
		str += label[label.length - 1] + "\n";
		pw.print(str);
	}

	private static void printResurt(PrintWriter pw, int keySize, long[] time) {
		String str = keySize + ", ";
		str += (time[1] - time[0]) + ", ";// MKP
		str += (time[2] - time[1]) + ", ";// SKP
		str += (time[3] - time[2]) + ", ";// SSK
		str += (time[4] - time[3]) + ", ";// MSK
		str += (time[4] - time[0]) + "\n";// TOTAL
		pw.print(str);
	}

	private static void printKeyParams(PublicKey alicePubKey) {
		DHPublicKeySpec pks;
		try {
			pks = KeyFactory.getInstance(DH).getKeySpec(alicePubKey, DHPublicKeySpec.class);
			System.out.println("g:" + pks.getG() + ", \np:" + pks.getP());
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
}

class Param {
	public static void measureTime() throws IOException {
		String OUTPUT = "resultDH2.csv";
		int NUM_RUN = 50;
		int NUM_CONDITION = 10;

		PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(OUTPUT)));
		printHeader(pw);

		Random random = new SecureRandom();
		for (int i = 0; i < NUM_CONDITION; i++) {
			int keysize = 512 * (i + 1);
			BigInteger p = BigInteger.probablePrime(keysize, random);
			BigInteger g = ModMatGen.randomBInt(random, p);
			DHParameterSpec params = new DHParameterSpec(p, g);
			System.out.println("p:" + p + ", g:" + g + ", size:" + keysize);

			for (int j = 0; j < NUM_RUN; j++)
				try {
					printResurt(pw, params, keysize, run(params));
				} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
					e.printStackTrace();
				}

		}
		pw.flush();
		pw.close();
		System.out.println("End");
	}

	static String DH = "DH";

	private static long[] run(DHParameterSpec params)
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
		long[] time = new long[5];
		KeyPairGenerator keyGen;
		KeyAgreement keyAgr;

		// Bob's makes key pair.
		time[0] = System.currentTimeMillis();
		keyGen = KeyPairGenerator.getInstance(DH);
		keyGen.initialize(params);
		KeyPair BobKeyPair = keyGen.generateKeyPair();
		// Bob sends his public key to Alice.
		PublicKey BobPubKey = BobKeyPair.getPublic();

		// Alice makes her key pair.
		time[1] = System.currentTimeMillis();
		keyGen = KeyPairGenerator.getInstance(DH);
		keyGen.initialize(params);
		KeyPair AliceKeyPair = keyGen.generateKeyPair();
		// Alice sends his public key to Bob.
		PublicKey AlicePubKey = AliceKeyPair.getPublic();

		// Alice calculates SSK.
		time[2] = System.currentTimeMillis();
		keyAgr = KeyAgreement.getInstance(DH);
		keyAgr.init(AliceKeyPair.getPrivate());
		keyAgr.doPhase(BobPubKey, true);
		byte[] ASK = keyAgr.generateSecret();

		// Bob calculates SSK.
		time[3] = System.currentTimeMillis();
		keyAgr = KeyAgreement.getInstance(DH);
		keyAgr.init(BobKeyPair.getPrivate());
		keyAgr.doPhase(AlicePubKey, true);
		byte[] BSK = keyAgr.generateSecret();

		time[4] = System.currentTimeMillis();

		System.out.println("Key size" + ASK.length * 8);

		if (!Arrays.equals(ASK, BSK))
			throw new RuntimeException("Keys are not equals.");
		return time;
	}

	private static void printHeader(PrintWriter pw) {
		String[] label = { "p", "g", "size", "MKP", "SKP", "SSK", "MSK", "Total" };
		String str = "";
		for (int i = 0; i < label.length - 1; i++)
			str += label[i] + ", ";
		str += label[label.length - 1] + "\n";
		pw.print(str);
	}

	private static void printResurt(PrintWriter pw, DHParameterSpec params, int keysize, long[] time) {
		String str = params.getP() + ", " + params.getG() + ", " + keysize + ", ";
		str += (time[1] - time[0]) + ", ";// MKP
		str += (time[2] - time[1]) + ", ";// SKP
		str += (time[3] - time[2]) + ", ";// SSK
		str += (time[4] - time[3]) + ", ";// MSK
		str += (time[4] - time[0]) + "\n";// TOTAL
		pw.print(str);
	}

	private static void printKeyParams(PublicKey alicePubKey) {
		DHPublicKeySpec pks;
		try {
			pks = KeyFactory.getInstance(DH).getKeySpec(alicePubKey, DHPublicKeySpec.class);
			System.out.println("g:" + pks.getG() + ", \np:" + pks.getP());
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
}
