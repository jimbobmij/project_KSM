package crypto.ssa5.spec;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import crypto.ssa5.interfaces.SAA5MasterPublicKey;
import matrix.ModularMatrix;

public class SAA5noSESlavePublicKeyParameterSpec implements AlgorithmParameterSpec {
	private final SAA5ParameterSpec params;
	private final ModularMatrix[] yB2;

	public SAA5noSESlavePublicKeyParameterSpec(PublicKey masterPubKey) throws InvalidKeyException {
		if (!(masterPubKey instanceof SAA5MasterPublicKey))
			throw new InvalidKeyException();
		this.params = ((SAA5MasterPublicKey) masterPubKey).getParams();
		this.yB2 = ((SAA5MasterPublicKey) masterPubKey).getYB2();
	}

	public final SAA5ParameterSpec getParams() {
		return params;
	}

	public final ModularMatrix[] getYB2() {
		return yB2;
	}
}
