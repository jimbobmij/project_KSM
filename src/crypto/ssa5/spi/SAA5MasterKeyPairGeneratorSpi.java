package crypto.ssa5.spi;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Random;

import crypto.ssa5.spec.SAA5ParameterSpec;
import matrix.ModularMatrix;
import matrix.generator.ModMatGen;
import matrix.generator.rule.NoRules;

public class SAA5MasterKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
	private SAA5ParameterSpec params;
	private Random random;

	@Override
	public void initialize(int keysize, SecureRandom random) {
		if (keysize < 512 || keysize % 512 != 0)
			throw new InvalidParameterException(
					"SSA5 key size must be multiple of 512. The specific key size " + keysize + " is not supported");
		int bitLength = keysize / 256;
		int dim = 16;
		int keyLength = 5;

		// key length is 5.
		// TODO : 'probablePrime' should not be used to gain the prime number.
		this.params = new SAA5ParameterSpec(dim, BigInteger.probablePrime(bitLength - 1, random), keyLength);
		this.random = random;
	}

	@Override
	public void initialize(AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidAlgorithmParameterException {
		if (!(params instanceof SAA5ParameterSpec))
			new InvalidAlgorithmParameterException();
		this.params = (SAA5ParameterSpec) params;
		this.random = random;
	}

	@Override
	public KeyPair generateKeyPair() {
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

		PrivateKey priK = new MasterPrivateKey(params, NB[1], xB);

		// Create Public Key
		ModularMatrix[] yB2 = new ModularMatrix[I];
		for (int j = 0; j < I; j++)
			yB2[j] = A[j].multi(NB[0], q).schurExp(c, p);

		ModularMatrix[] yB3 = new ModularMatrix[I];
		for (int j = 0; j < I; j++)
			yB3[j] = A[j].multi(xB, q).schurExp(c, p);

		PublicKey pubK = new MasterPublicKey(params, yB2, yB3);

		return new KeyPair(pubK, priK);
	}
}
