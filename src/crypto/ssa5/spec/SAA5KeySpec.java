package crypto.ssa5.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

class SAA5KeySpec implements KeySpec {
	protected final SAA5ParameterSpec params;

	public SAA5KeySpec(SAA5ParameterSpec params) {
		this.params = params;
	}

	public final int getD() {
		return params.d;
	}

	public final BigInteger getP() {
		return params.p;
	}

	public final int getI() {
		return params.I;
	}
}
