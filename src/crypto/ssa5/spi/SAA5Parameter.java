package crypto.ssa5.spi;

import java.math.BigInteger;

import crypto.ssa5.spec.SAA5ParameterSpec;

public class SAA5Parameter extends SAA5ParameterSpec {
	public SAA5Parameter(int dim, BigInteger mod, int keyLength) {
		super(dim, mod, keyLength);
	}
}
