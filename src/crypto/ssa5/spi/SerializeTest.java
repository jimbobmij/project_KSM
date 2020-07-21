package crypto.ssa5.spi;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import crypto.ssa5.spec.SAA5ParameterSpec;
import matrix.ModularMatrix;
import matrix.generator.ModMatGen;
import matrix.generator.rule.NoRules;

public class SerializeTest {
	public static void main(String[] args) {
		int suc = 0;
		int num = 1000;

		Random random = new Random();
		for (int i = 0; i < num; i++) {
			if (modmat(random) && params(random) && mrk(random) && muk(random) && srk(random) && suk(random)
					&& ssk(random))
				suc++;
		}
		System.out.println(suc + "/" + num);
	}

	// Mod Matrix : OK
	static boolean modmat(Random random) {
		int d = ModMatGen.randomInt(random, 2, 10);
		int bitLength = ModMatGen.randomInt(random, 2, 256);
		BigInteger p = BigInteger.probablePrime(bitLength, random);

		ModularMatrix obj1 = ModMatGen.createMatrix(new NoRules(random, p), d, p);
		byte[] array = obj1.toByteArray();

		ModularMatrix obj2 = new ModularMatrix(array);
		if (obj1.byteArrayLength() != array.length)
			throw new RuntimeException(obj1.byteArrayLength() + "(" + array.length + ")");
		return obj1.equals(obj2);
	}

	// Common Params : OK
	static boolean params(Random random) {
		int d = ModMatGen.randomInt(random, 0, Byte.MAX_VALUE);
		int bitLength = ModMatGen.randomInt(random, 2, 256);
		BigInteger p = BigInteger.probablePrime(bitLength, random);
		int I = ModMatGen.randomInt(random, 0, Short.MAX_VALUE);

		SAA5ParameterSpec obj1 = new SAA5ParameterSpec(d, p, I);
		byte[] array = obj1.toByteArray();

		SAA5ParameterSpec obj2 = new SAA5ParameterSpec(array);
		if (obj1.byteArrayLength() != array.length)
			throw new RuntimeException(obj1.byteArrayLength() + "(" + array.length + ")");
		return obj1.equals(obj2);
	}

	// MasterPriKey : OK
	static boolean mrk(Random random) {
		int d = ModMatGen.randomInt(random, 2, 10);
		int bitLength = ModMatGen.randomInt(random, 2, 256);
		BigInteger p = BigInteger.probablePrime(bitLength, random);
		int I = ModMatGen.randomInt(random, 2, 10);

		SAA5ParameterSpec params = new SAA5ParameterSpec(d, p, I);

		ModularMatrix xB = ModMatGen.createMatrix(new NoRules(random, p), d, p);
		ModularMatrix NB = ModMatGen.createMatrix(new NoRules(random, p), d, p);

		MasterPrivateKey obj1 = new MasterPrivateKey(params, xB, NB);
		byte[] array = obj1.toByteArray();
		MasterPrivateKey obj2 = new MasterPrivateKey(array);

		if (obj1.byteArrayLength() != array.length)
			throw new RuntimeException(obj1.byteArrayLength() + "(" + array.length + ")");
		return obj1.equals(obj2);
	}

	// MasterPubKey : OK
	static boolean muk(Random random) {
		int d = ModMatGen.randomInt(random, 2, 10);
		int bitLength = ModMatGen.randomInt(random, 2, 256);
		BigInteger p = BigInteger.probablePrime(bitLength, random);
		int I = ModMatGen.randomInt(random, 2, 10);

		SAA5ParameterSpec params = new SAA5ParameterSpec(d, p, I);

		ModularMatrix[] yB2 = new ModularMatrix[I];
		ModularMatrix[] yB3 = new ModularMatrix[I];
		for (int i = 0; i < I; i++) {
			yB2[i] = ModMatGen.createMatrix(new NoRules(random, p), d, p);
			yB3[i] = ModMatGen.createMatrix(new NoRules(random, p), d, p);
		}

		MasterPublicKey obj1 = new MasterPublicKey(params, yB2, yB3);
		byte[] array = obj1.toByteArray();
		MasterPublicKey obj2 = new MasterPublicKey(array);

		if (obj1.byteArrayLength() != array.length)
			throw new RuntimeException(obj1.byteArrayLength() + "(" + array.length + ")");
		return obj1.equals(obj2);
	}

	// SlavePriKey : OK
	static boolean srk(Random random) {
		int d = ModMatGen.randomInt(random, 2, 10);
		int bitLength = ModMatGen.randomInt(random, 2, 256);
		BigInteger p = BigInteger.probablePrime(bitLength, random);
		int I = ModMatGen.randomInt(random, 2, 10);

		SAA5ParameterSpec params = new SAA5ParameterSpec(d, p, I);

		ModularMatrix[] xA = new ModularMatrix[I];
		for (int i = 0; i < I; i++)
			xA[i] = ModMatGen.createMatrix(new NoRules(random, p), d, p);

		SlavePrivateKey obj1 = new SlavePrivateKey(params, xA);
		byte[] array = obj1.toByteArray();
		SlavePrivateKey obj2 = new SlavePrivateKey(array);

		if (obj1.byteArrayLength() != array.length)
			throw new RuntimeException(obj1.byteArrayLength() + "(" + array.length + ")");
		return obj1.equals(obj2);
	}

	// SlavePubKey : OK
	static boolean suk(Random random) {
		int d = ModMatGen.randomInt(random, 2, 10);
		int bitLength = ModMatGen.randomInt(random, 2, 256);
		BigInteger p = BigInteger.probablePrime(bitLength, random);
		int I = ModMatGen.randomInt(random, 2, 10);

		SAA5ParameterSpec params = new SAA5ParameterSpec(d, p, I);

		ModularMatrix yB = ModMatGen.createMatrix(new NoRules(random, p), d, p);

		SlavePublicKey obj1 = new SlavePublicKey(params, yB);
		byte[] array = obj1.toByteArray();
		SlavePublicKey obj2 = new SlavePublicKey(array);

		if (obj1.byteArrayLength() != array.length)
			throw new RuntimeException(obj1.byteArrayLength() + "(" + array.length + ")");
		return obj1.equals(obj2);
	}

	// SSK : OK
	static boolean ssk(Random random) {
		int d = ModMatGen.randomInt(random, 2, 10);
		int bitLength = ModMatGen.randomInt(random, 2, 256);
		BigInteger p = BigInteger.probablePrime(bitLength, random);
		int I = ModMatGen.randomInt(random, 2, 10);

		SAA5ParameterSpec params = new SAA5ParameterSpec(d, p, I);

		ModularMatrix ssk = ModMatGen.createMatrix(new NoRules(random, p), d, p);

		SecretSharedKey obj1 = new SecretSharedKey(params, ssk);
		byte[] array = obj1.toByteArray();
		SecretSharedKey obj2 = new SecretSharedKey(array);

		if (obj1.byteArrayLength() != array.length)
			throw new RuntimeException(obj1.byteArrayLength() + "(" + array.length + ")");
		return obj1.equals(obj2);
	}
}
