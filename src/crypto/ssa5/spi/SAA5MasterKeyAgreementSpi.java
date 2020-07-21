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

import crypto.ssa5.interfaces.SAA5MasterPrivateKey;
import crypto.ssa5.interfaces.SAA5SlavePublicKey;
import crypto.ssa5.spec.SAA5ParameterSpec;
import matrix.ModularMatrix;

public class SAA5MasterKeyAgreementSpi extends KeyAgreementSpi {
	private SAA5ParameterSpec params;
	private ModularMatrix NB;
	private ModularMatrix xB;
	private ModularMatrix ssk;

	@Override
	protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
		if (!(key instanceof SAA5MasterPrivateKey))
			throw new InvalidKeyException();
		SAA5MasterPrivateKey mpk = (SAA5MasterPrivateKey) key;
		params = mpk.getParams();
		NB = mpk.getNB();
		xB = mpk.getXB();
	}

	@Override
	protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		throw new InvalidAlgorithmParameterException("Not allowed to change parameters from what the key has.");
	}

	@Override
	protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
		if (params == null || NB == null || xB == null)
			throw new IllegalStateException();
		if (!(key instanceof SAA5SlavePublicKey))
			throw new InvalidKeyException();
		if (!params.equals(((SAA5SlavePublicKey) key).getParams()))
			throw new InvalidKeyException();

		BigInteger p = params.getP();
		ModularMatrix yA = ((SAA5SlavePublicKey) key).getYA();
		ssk = yA.exponent(NB, p).exponent(xB, p);
		return new SecretSharedKey(params, ssk);
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
