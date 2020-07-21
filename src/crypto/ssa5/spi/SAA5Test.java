package crypto.ssa5.spi;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.KeyAgreement;

import crypto.ssa5.SAA5;
import crypto.ssa5.interfaces.SAA5MasterPrivateKey;
import crypto.ssa5.interfaces.SAA5SlavePrivateKey;
import crypto.ssa5.spec.SAA5ParameterSpec;
import crypto.ssa5.spec.SAA5SlavePublicKeyParameterSpec;
import matrix.ModularMatrix;
import matrix.generator.ModMatGen;
import matrix.generator.rule.NoRules;

public class SAA5Test {
	public static void main(String[] args) {
		try {
			Keysize.measureTime();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void run() throws IOException {
		Random random = new SecureRandom();
		int d = 5;
		BigInteger p = new BigInteger("2147483647");
		int I = 3;
		BigInteger[][] data;

		// Master Key pair
		BigInteger q = p.subtract(BigInteger.ONE);
		ModularMatrix xB = ModMatGen.createMatrix(new NoRules(random, p), d, p);
		System.out.println("xB=");
		xB.print();

		ModularMatrix[] A = new ModularMatrix[I];
		for (int i = 0; i < I; i++) {
			A[i] = ModMatGen.makeNotInvertibleMatrix(random, d, p);
			System.out.println("A[" + i + "]=");
			A[i].print();
		}
		ModularMatrix[] NB = ModMatGen.makeInvertibleMatrix(random, d, q);
		System.out.println("NB=");
		NB[0].print();
		System.out.println("NB-1=");
		NB[1].print();

		BigInteger c = ModMatGen.randomBInt(random, p);
		System.out.println("c=");
		System.out.println(c);

		ModularMatrix[] yB2 = new ModularMatrix[I];
		for (int j = 0; j < I; j++) {
			yB2[j] = A[j].multi(NB[0], q).schurExp(c, p);
			System.out.println("yB2[" + j + "]=");
			yB2[j].print();
		}
		ModularMatrix[] yB3 = new ModularMatrix[I];
		for (int j = 0; j < I; j++) {
			yB3[j] = A[j].multi(xB, q).schurExp(c, p);
			System.out.println("yB3[" + j + "]=");
			yB3[j].print();
		}

		// Slave Key pair
		ModularMatrix[] xA = new ModularMatrix[I];
		for (int i = 0; i < I; i++) {
			xA[i] = ModMatGen.createMatrix(new NoRules(random, p), d, p);
			System.out.println("xA[" + i + "]=");
			xA[i].print();
		}

		data = new BigInteger[d][d];
		for (int i = 0; i < d; i++)
			for (int j = 0; j < d; j++) {
				BigInteger v = BigInteger.ONE;
				for (int t = 0; t < I; t++)
					for (int k = 0; k < d; k++)
						v = v.multiply(modPow(yB2[t].get(k, j), xA[t].get(i, k), p));
				data[i][j] = v;
			}
		ModularMatrix yA = new ModularMatrix(data, p);
		System.out.println("yA=");
		yA.print();

		data = new BigInteger[d][d];
		for (int i = 0; i < d; i++)
			for (int j = 0; j < d; j++) {
				BigInteger v = BigInteger.ONE;
				for (int t = 0; t < I; t++)
					for (int k = 0; k < d; k++)
						v = v.multiply(modPow(yB3[t].get(k, j), xA[t].get(i, k), p));
				data[i][j] = v;
			}
		ModularMatrix sssk = new ModularMatrix(data, p);
		System.out.println("k_A=");
		sssk.print();

		// Master SSK
		ModularMatrix M = yA.exponent(NB[1], p);
		System.out.println("M=");
		M.print();

		ModularMatrix mssk = M.exponent(xB, p);
		System.out.println("k_B=");
		mssk.print();

		if (!mssk.equals(sssk))
			throw new RuntimeException("Keys are not equals.");
	}

	private static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger mod) {
		if (base.equals(BigInteger.ZERO))
			return BigInteger.ZERO;
		else
			return base.modPow(exponent, mod);
	}
}

class Param {
	public static void measureTime() throws IOException {
		String OUTPUT = "resultP.csv";
		int NUM_RUN = 100;
		int NUM_CONDITION = 20;
		int VAR_SWITCH = 0x010;

		PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(OUTPUT)));
		printHeader(pw);

		for (int i = 0; i < NUM_CONDITION; i++) {
			// set params
			int d = condD(i, VAR_SWITCH);
			BigInteger p = condP(i, VAR_SWITCH);
			int I = condI(i, VAR_SWITCH);

			SAA5ParameterSpec params = new SAA5ParameterSpec(d, p, I);
			System.out.println("d:" + d + ", p:" + (p.bitLength() + 1) + ", I:" + I + ", size:" + keyLength(params));

			for (int j = 0; j < NUM_RUN; j++) {
				try {
					System.out.println(i + "," + j);
					printResurt(pw, params, run(params));
				} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
					e.printStackTrace();
				}

			}
		}
		pw.flush();
		pw.close();
		System.out.println("End");
	}

	private static long[] run(SAA5ParameterSpec params)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
		Provider provider = new SAA5();
		KeyPairGenerator keyGen;
		long[] time = new long[5];

		// Master Key pair
		time[0] = System.currentTimeMillis();

		keyGen = KeyPairGenerator.getInstance("SAA5master", provider);
		keyGen.initialize(params);
		KeyPair masterKeyPair = keyGen.generateKeyPair();

		// Send Public Key to Slave
		byte[] masterPublicKeyArray = masterKeyPair.getPublic().getEncoded();

		// Slave Key pair
		time[1] = System.currentTimeMillis();

		PublicKey masterPubKey = new MasterPublicKey(masterPublicKeyArray);

		keyGen = KeyPairGenerator.getInstance("SAA5slave", provider);
		keyGen.initialize(new SAA5SlavePublicKeyParameterSpec(masterPubKey));
		KeyPair slaveKeyPair = keyGen.generateKeyPair();

		// Slave SSK
		time[2] = System.currentTimeMillis();

		SAA5SlavePrivateKey slavePriKey = (SAA5SlavePrivateKey) slaveKeyPair.getPrivate();
		KeyAgreement slaveKeyAgreement = new KeyAgreement(new SAA5SlaveKeyAgreementSpi(), provider, "SAA5slave") {
		};
		slaveKeyAgreement.init(slavePriKey);
		Key slaveKey = slaveKeyAgreement.doPhase(masterPubKey, true);

		// Send Public Key to Master
		byte[] slavePublicKeyArray = slaveKeyPair.getPublic().getEncoded();

		// Master SSK
		time[3] = System.currentTimeMillis();
		SAA5MasterPrivateKey masterPriKey = (SAA5MasterPrivateKey) masterKeyPair.getPrivate();
		PublicKey slavePubKey = new SlavePublicKey(slavePublicKeyArray);

		KeyAgreement masterKeyAgreement = new KeyAgreement(new SAA5MasterKeyAgreementSpi(), provider, "SAA5master") {
		};
		masterKeyAgreement.init(masterPriKey);
		Key masterKey = masterKeyAgreement.doPhase(slavePubKey, true);

		time[4] = System.currentTimeMillis();

		if (!((SecretSharedKey) slaveKey).getKey().equals(((SecretSharedKey) masterKey).getKey()))
			throw new RuntimeException("Keys are not equals.");
		int keyLength = ((SecretSharedKey) masterKey).getKey().toKeyByteArray().length * 8;
		if (keyLength != keyLength(params))
			throw new RuntimeException("Keys length is not collect : " + keyLength + "(" + keyLength(params) + ")");
		return time;
	}

	private static void printHeader(PrintWriter pw) {
		String[] label ={ "dim", "bit.length", "I", "KeySize", "MKP", "SKP", "SSK", "MSK", "Total" };
		String str = "";
		for (int i = 0; i < label.length - 1; i++)
			str += label[i] + ", ";
		str += label[label.length - 1] + "\n";
		pw.print(str);
	}

	private static void printResurt(PrintWriter pw, SAA5ParameterSpec params, long[] time) {
		String str = params.getD() + ", " + params.getP().bitLength() + 1 + ", " + params.getI() + ", "
				+ keyLength(params) + ", ";
		str += (time[1] - time[0]) + ", ";// MKP
		str += (time[2] - time[1]) + ", ";// SKP
		str += (time[3] - time[2]) + ", ";// SSK
		str += (time[4] - time[3]) + ", ";// MSK
		str += (time[4] - time[0]) + "\n";// TOTAL
		pw.print(str);
	}

	private static int keyLength(SAA5ParameterSpec params) {
		return ((params.getP().bitLength() + 1) + 7) / 8 * params.getD() * params.getD() * 8;
	}

	private static int condD(int cond, int swt) {
		if ((swt & 0x100) > 0)
			return (cond + 2);
		else
			return 10;
	}

	private static BigInteger condP(int cond, int swt) {
		if ((swt & 0x010) > 0)
			return BigInteger.probablePrime((cond + 1) * 8 - 1, new Random());
		else
			return new BigInteger("2147483647");
	}

	private static int condI(int cond, int swt) {
		if ((swt & 0x001) > 0)
			return 20 * (cond + 1);
		else
			return 10;
	}
}

class DimP {
	public static void measureTime() throws IOException {
		String OUTPUT = "resultDP.csv";
		int NUM_RUN = 100;
		int NUM_CONDITION = 5;

		PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(OUTPUT)));
		printHeader(pw);

		for (int i = 0; i < NUM_CONDITION; i++) {
			int d = (int) Math.pow(2, i + 1);
			int keysize = 16384;
			BigInteger p = BigInteger.probablePrime(keysize / (d * d) - 1, new Random());
			int I = 10;

			SAA5ParameterSpec params = new SAA5ParameterSpec(d, p, I);
			System.out.println("d:" + d + ", p:" + (p.bitLength() + 1) + ", I:" + I + ", size:" + keyLength(params));

			for (int j = 0; j < NUM_RUN; j++) {
				System.out.println(i + "," + j);
				printResurt(pw, params, run(params));
			}
		}
		pw.flush();
		pw.close();
		System.out.println("End");
	}

	private static long[] run(SAA5ParameterSpec params) {
		long[] time = new long[5];

		Random random = new SecureRandom();
		int d = params.getD();
		BigInteger p = params.getP();
		int I = params.getI();
		BigInteger[][] data;

		// Master Key pair
		time[0] = System.currentTimeMillis();

		BigInteger q = p.subtract(BigInteger.ONE);
		ModularMatrix xB = ModMatGen.createMatrix(new NoRules(random, p), d, p);
		ModularMatrix[] A = new ModularMatrix[I];
		for (int i = 0; i < I; i++)
			A[i] = ModMatGen.makeNotInvertibleMatrix(random, d, p);
		ModularMatrix[] NB = ModMatGen.makeInvertibleMatrix(random, d, q);
		BigInteger c = ModMatGen.randomBInt(random, p);

		ModularMatrix[] yB2 = new ModularMatrix[I];
		for (int j = 0; j < I; j++)
			yB2[j] = A[j].multi(NB[0], q).schurExp(c, p);
		ModularMatrix[] yB3 = new ModularMatrix[I];
		for (int j = 0; j < I; j++)
			yB3[j] = A[j].multi(xB, q).schurExp(c, p);

		// Slave Key pair
		time[1] = System.currentTimeMillis();
		ModularMatrix[] xA = new ModularMatrix[I];
		for (int i = 0; i < I; i++)
			xA[i] = ModMatGen.createMatrix(new NoRules(random, p), d, p);

		data = new BigInteger[d][d];
		for (int i = 0; i < d; i++)
			for (int j = 0; j < d; j++) {
				BigInteger v = BigInteger.ONE;
				for (int t = 0; t < I; t++)
					for (int k = 0; k < d; k++)
						v = v.multiply(modPow(yB2[t].get(k, j), xA[t].get(i, k), p));
				data[i][j] = v;
			}
		ModularMatrix yA = new ModularMatrix(data, p);

		// Slave SSK
		time[2] = System.currentTimeMillis();

		data = new BigInteger[d][d];
		for (int i = 0; i < d; i++)
			for (int j = 0; j < d; j++) {
				BigInteger v = BigInteger.ONE;
				for (int t = 0; t < I; t++)
					for (int k = 0; k < d; k++)
						v = v.multiply(modPow(yB3[t].get(k, j), xA[t].get(i, k), p));
				data[i][j] = v;
			}
		ModularMatrix sssk = new ModularMatrix(data, p);

		// Master SSK
		time[3] = System.currentTimeMillis();

		ModularMatrix mssk = yA.exponent(NB[1], p).exponent(xB, p);

		time[4] = System.currentTimeMillis();

		if (!mssk.equals(sssk))
			throw new RuntimeException("Keys are not equals.");
		return time;
	}

	private static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger mod) {
		if (base.equals(BigInteger.ZERO))
			return BigInteger.ZERO;
		else
			return base.modPow(exponent, mod);
	}

	private static void printHeader(PrintWriter pw) {
		String[] label = { "dim", "bit.length", "I", "KeySize", "MKP", "SKP", "SSK", "MSK", "Total" };
		String str = "";
		for (int i = 0; i < label.length - 1; i++)
			str += label[i] + ", ";
		str += label[label.length - 1] + "\n";
		pw.print(str);
	}

	private static void printResurt(PrintWriter pw, SAA5ParameterSpec params, long[] time) {
		String str = params.getD() + ", " + params.getP().bitLength() + 1 + ", " + params.getI() + ", "
				+ keyLength(params) + ", ";
		str += (time[1] - time[0]) + ", ";// MKP
		str += (time[2] - time[1]) + ", ";// SKP
		str += (time[3] - time[2]) + ", ";// SSK
		str += (time[4] - time[3]) + ", ";// MSK
		str += (time[4] - time[0]) + "\n";// TOTAL
		pw.print(str);
	}

	private static int keyLength(SAA5ParameterSpec params) {
		return ((params.getP().bitLength() + 1) + 7) / 8 * params.getD() * params.getD() * 8;
	}

	private static int condD(int cond, int swt) {
		if ((swt & 0x100) > 0)
			return (cond + 2);
		else
			return 10;
	}

	private static BigInteger condP(int cond, int swt) {
		if ((swt & 0x010) > 0)
			return BigInteger.probablePrime((cond + 1) * 8 - 1, new Random());
		else
			return new BigInteger("2147483647");
	}

	private static int condI(int cond, int swt) {
		if ((swt & 0x001) > 0)
			return 20 * (cond + 1);
		else
			return 10;
	}
}

class Keysize {
	public static void measureTime() throws IOException {
		String OUTPUT = "resultS.csv";
		int NUM_RUN = 100;
		int NUM_CONDITION = 10;

		PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(OUTPUT)));
		Keysize.printHeader(pw);
		for (int i = 0; i < NUM_CONDITION; i++) {

			int keysize = 512 * (i + 1);
			System.out.println("size:" + keysize);
			for (int j = 0; j < NUM_RUN; j++) {
				long begin = System.currentTimeMillis();
				try {
					printResurt(pw, keysize, run(keysize));
				} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
					e.printStackTrace();
				}
				long end = System.currentTimeMillis();
				System.out.println(j + "th TRIAL" + "[" + keysize + " bits]:" + (end - begin));
			}
		}
		pw.flush();
		pw.close();
		System.out.println("End");
	}

	private static long[] run(int keysize)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
		Provider provider = new SAA5();
		KeyPairGenerator keyGen;
		long[] time = new long[5];

		// Master Key pair
		time[0] = System.currentTimeMillis();

		keyGen = KeyPairGenerator.getInstance("SAA5master", provider);
		keyGen.initialize(keysize);
		KeyPair masterKeyPair = keyGen.generateKeyPair();

		// Send Public Key to Slave
		byte[] masterPublicKeyArray = masterKeyPair.getPublic().getEncoded();

		// Slave Key pair
		time[1] = System.currentTimeMillis();

		PublicKey masterPubKey = new MasterPublicKey(masterPublicKeyArray);

		keyGen = KeyPairGenerator.getInstance("SAA5slave", provider);
		keyGen.initialize(new SAA5SlavePublicKeyParameterSpec(masterPubKey));
		KeyPair slaveKeyPair = keyGen.generateKeyPair();

		// Slave SSK
		time[2] = System.currentTimeMillis();

		SAA5SlavePrivateKey slavePriKey = (SAA5SlavePrivateKey) slaveKeyPair.getPrivate();
		KeyAgreement slaveKeyAgreement = new KeyAgreement(new SAA5SlaveKeyAgreementSpi(), provider, "SAA5slave") {
		};
		slaveKeyAgreement.init(slavePriKey);
		Key slaveKey = slaveKeyAgreement.doPhase(masterPubKey, true);

		// Send Public Key to Master
		byte[] slavePublicKeyArray = slaveKeyPair.getPublic().getEncoded();

		// Master SSK
		time[3] = System.currentTimeMillis();
		SAA5MasterPrivateKey masterPriKey = (SAA5MasterPrivateKey) masterKeyPair.getPrivate();
		PublicKey slavePubKey = new SlavePublicKey(slavePublicKeyArray);

		KeyAgreement masterKeyAgreement = new KeyAgreement(new SAA5MasterKeyAgreementSpi(), provider, "SAA5master") {
		};
		masterKeyAgreement.init(masterPriKey);
		Key masterKey = masterKeyAgreement.doPhase(slavePubKey, true);

		time[4] = System.currentTimeMillis();

		if (!((SecretSharedKey) slaveKey).getKey().equals(((SecretSharedKey) masterKey).getKey()))
			throw new RuntimeException("Keys are not equals.");
		int keyLength = ((SecretSharedKey) masterKey).getKey().toKeyByteArray().length * 8;
		if (keyLength != keysize)
			throw new RuntimeException("Keys length is not collect : " + keyLength + "(" + keysize + ")");
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

	private static void printResurt(PrintWriter pw, int keysize, long[] time) {
		String str = keysize + ", ";
		str += (time[1] - time[0]) + ", ";// MKP
		str += (time[2] - time[1]) + ", ";// SKP
		str += (time[3] - time[2]) + ", ";// SSK
		str += (time[4] - time[3]) + ", ";// MSK
		str += (time[4] - time[0]) + "\n";// TOTAL
		pw.print(str);
		//System.out.println(str);
	}
}
