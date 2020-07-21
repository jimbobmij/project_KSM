package crypto.ssa5.spi;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import crypto.ssa5.spec.SAA5ParameterSpec;
import matrix.ModularMatrix;
import matrix.generator.ModMatGen;
import matrix.generator.rule.NoRules;

public class SAA5FuncTest {
	public static void main(String[] args) {
		new SAA5FuncTest();
	}

	Random random = new SecureRandom();

	SAA5FuncTest() {
		long begin = System.currentTimeMillis();
		System.out.println("SAA5FuncTest");
		int num = 1000;
		int cnt = 0;
		for (int i = 0; i < num; i++)
			cnt += test();
		System.out.println(cnt + "/" + num);
		long end = System.currentTimeMillis();
		System.out.println( "time" + "]:" + (end - begin));
	}

	int test() {


		// Master
		SAA5ParameterSpec params = new SAA5ParameterSpec(5, BigInteger.probablePrime(64, random), 5);
		MasterKeyPair MKP = createMKP(params);
		byte[] mpkArray = MKP.pub.toByteArray();

		// Slave
		MasterPublicKey mpk = new MasterPublicKey(mpkArray);
		SlaveKeyPair SKP = createSKP(params, mpk);
		SecretSharedKey SK = createSK(params, SKP.pri, mpk);
		SK.getKey().print();
		byte[] spkArray = SKP.pub.toByteArray();

		// Master
		SlavePublicKey spk = new SlavePublicKey(spkArray);
		SecretSharedKey MK = createMK(params, MKP.pri, spk);
		MK.getKey().print();

		if (SK.getKey().equals(MK.getKey()))
			return 1;
		else
			return 0;

	}

	private MasterKeyPair createMKP(SAA5ParameterSpec params) {
		int d = params.getD();
		BigInteger p = params.getP();
		BigInteger q = p.subtract(BigInteger.ONE);
		int I = params.getI();

		// Create 4 Private Keys
		ModularMatrix xB = ModMatGen.createMatrix(new NoRules(random, p), d, p);
		ModularMatrix[] A = new ModularMatrix[I];
		for (int i = 0; i < I; i++)
			A[i] = ModMatGen.makeNotInvertibleMatrix(random, d, p);
		ModularMatrix[] NB = ModMatGen.makeInvertibleMatrix(random, d, q);
		BigInteger c = ModMatGen.randomBInt(random, p);

		// Create Public Key
		ModularMatrix[] yB2 = new ModularMatrix[I];
		for (int j = 0; j < I; j++)
			yB2[j] = A[j].multi(NB[0], q).schurExp(c, p);

		ModularMatrix[] yB3 = new ModularMatrix[I];
		for (int j = 0; j < I; j++)
			yB3[j] = A[j].multi(xB, q).schurExp(c, p);

		return new MasterKeyPair(new MasterPublicKey(params, yB2, yB3), new MasterPrivateKey(params, NB[1], xB));

	}

	class MasterKeyPair {
		MasterPublicKey pub;
		MasterPrivateKey pri;

		MasterKeyPair(MasterPublicKey muk, MasterPrivateKey mrk) {
			pub = muk;
			pri = mrk;
		}
	}

	private SecretSharedKey createMK(SAA5ParameterSpec params, MasterPrivateKey mrk, SlavePublicKey suk) {
		BigInteger p = params.getP();

		ModularMatrix xB = mrk.getXB();
		ModularMatrix NB = mrk.getNB();
		ModularMatrix yA = suk.getYA();

		return new SecretSharedKey(params, yA.exponent(NB, p).exponent(xB, p));
	}

	class SlaveKeyPair {
		SlavePublicKey pub;
		SlavePrivateKey pri;

		SlaveKeyPair(SlavePublicKey suk, SlavePrivateKey srk) {
			pub = suk;
			pri = srk;
		}
	}

	private SlaveKeyPair createSKP(SAA5ParameterSpec params, MasterPublicKey mpk) {
		int d = params.getD();
		BigInteger p = params.getP();
		int I = params.getI();

		ModularMatrix[] xA = new ModularMatrix[I];
		for (int i = 0; i < I; i++)
			xA[i] = ModMatGen.createMatrix(new NoRules(random, p), d, p);

		ModularMatrix[] yB2 = mpk.getYB2();
		BigInteger[][] data = new BigInteger[d][d];
		for (int i = 0; i < d; i++)
			for (int j = 0; j < d; j++) {
				BigInteger v = BigInteger.ONE;
				for (int t = 0; t < I; t++)
					for (int k = 0; k < d; k++)
						v = v.multiply(modPow(yB2[t].get(k, j), xA[t].get(i, k), p));
				data[i][j] = v;
			}
		ModularMatrix yA = new ModularMatrix(data, p);

		return new SlaveKeyPair(new SlavePublicKey(params, yA), new SlavePrivateKey(params, xA));
	}

	private SecretSharedKey createSK(SAA5ParameterSpec params, SlavePrivateKey srk, MasterPublicKey muk) {
		int d = params.getD();
		BigInteger p = params.getP();
		int I = params.getI();

		ModularMatrix[] xA = srk.getXA();
		ModularMatrix[] yB3 = muk.getYB3();

		BigInteger[][] data = new BigInteger[d][d];
		for (int i = 0; i < d; i++)
			for (int j = 0; j < d; j++) {
				BigInteger v = BigInteger.ONE;
				for (int t = 0; t < I; t++)
					for (int k = 0; k < d; k++)
						v = v.multiply(modPow(yB3[t].get(k, j), xA[t].get(i, k), p));
				data[i][j] = v;
			}
		return new SecretSharedKey(params, new ModularMatrix(data, p));
	}

	private static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger mod) {
		if (base.equals(BigInteger.ZERO))
			return BigInteger.ZERO;
		else
			return base.modPow(exponent, mod);
	}
}
