package crypto.ssa5.spi;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import crypto.ssa5.interfaces.SAA5MasterPublicKey;
import crypto.ssa5.interfaces.SAA5SlavePrivateKey;
import crypto.ssa5.spec.SAA5ParameterSpec;
import matrix.ModularMatrix;

public class SAA5noSESlaveKeyAgreementSpi extends KeyAgreementSpi {
	private SAA5ParameterSpec params;
	private ModularMatrix[] xA;
	private ModularMatrix ssk;

	@Override
	protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
		if (!(key instanceof SAA5SlavePrivateKey))
			throw new InvalidKeyException();
		SAA5SlavePrivateKey spk = (SAA5SlavePrivateKey) key;
		params = spk.getParams();
		xA = spk.getXA();
	}

	@Override
	protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		throw new InvalidAlgorithmParameterException("Not allowed to change parameters from what the key has.");
	}

	@Override
	protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
		if (!(key instanceof SAA5MasterPublicKey))
			throw new InvalidKeyException();
		if (!params.equals(((SAA5MasterPublicKey) key).getParams()))
			throw new InvalidKeyException();

		int d = params.getD();
		BigInteger p = params.getP();
		int I = params.getI();
		ModularMatrix[] yB3 = ((SAA5MasterPublicKey) key).getYB3();

		ModularMatrix[] xAyB3 = new ModularMatrix[I];
		for (int j = 0; j < I; j++)
			xAyB3[j] = xA[j].multi(yB3[j], p);

		BigInteger[][] data = new BigInteger[d][d];

		for (int i = 0; i < d; i++)
			for (int j = 0; j < d; j++) {
				data[i][j] = BigInteger.ZERO;
			}

		for (int k = 0; k < I; k++)
			for (int i = 0; i < d; i++) {
				for (int j = 0; j < d; j++) {
					data[i][j] = data[i][j].add(xAyB3[k].get(i, j));
				}
			}


//		for (int i = 0; i < d; i++)
//			for (int j = 0; j < d; j++) {
//				BigInteger v = BigInteger.ONE;
//				for (int t = 0; t < I; t++)
//					for (int k = 0; k < d; k++)
//						v = v.multiply(modPow(yB3[t].get(k, j), xA[t].get(i, k), p));
//				data[i][j] = v;
//			}
		ssk = new ModularMatrix(data, p);

		return new SecretSharedKey(params, ssk);
	}

	private static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger mod) {
		if (base.equals(BigInteger.ZERO))
			return BigInteger.ZERO;
		else
			return base.modPow(exponent, mod);
	}

	@Override
	protected byte[] engineGenerateSecret() throws IllegalStateException {
		if (ssk == null)
			throw new IllegalStateException("Secret key is not genelated.");
		return ssk.toKeyByteArray();
	}

	@Override
	protected SecretKey engineGenerateSecret(String algorithm)
			throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
		return null;
	}

	@Override
	protected int engineGenerateSecret(byte[] sharedSecret, int offset)
			throws IllegalStateException, ShortBufferException {
		return 0;
	}
}
