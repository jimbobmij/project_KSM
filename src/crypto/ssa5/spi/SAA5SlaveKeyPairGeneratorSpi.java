package crypto.ssa5.spi;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Random;

import crypto.ssa5.spec.SAA5SlavePublicKeyParameterSpec;
import matrix.ModularMatrix;
import matrix.generator.ModMatGen;
import matrix.generator.rule.NoRules;

public class SAA5SlaveKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
	private SAA5SlavePublicKeyParameterSpec params;
	private Random random;

	@Override
	public void initialize(int keysize, SecureRandom random) {
		throw new RuntimeException("Parameters are needed.");
	}

	@Override
	public void initialize(AlgorithmParameterSpec params, SecureRandom random) {
		this.params = (SAA5SlavePublicKeyParameterSpec) params;
		this.random = random;
	}

	@Override
	public KeyPair generateKeyPair() {

		int d = params.getParams().getD();
		BigInteger p = params.getParams().getP();
		int I = params.getParams().getI();

		// Create Private Key
		ModularMatrix[] xA = new ModularMatrix[I];
		for (int i = 0; i < I; i++)
			xA[i] = ModMatGen.createMatrix(new NoRules(random, p), d, p);
		PrivateKey priK = new SlavePrivateKey(params.getParams(), xA);

		// Create Public Key
		ModularMatrix[] yB2 = params.getYB2();
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
		PublicKey pubK = new SlavePublicKey(params.getParams(), yA);

		return new KeyPair(pubK, priK);
	}

	private static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger mod) {
		if (base.equals(BigInteger.ZERO))
			return BigInteger.ZERO;
		else
			return base.modPow(exponent, mod);
	}
}
