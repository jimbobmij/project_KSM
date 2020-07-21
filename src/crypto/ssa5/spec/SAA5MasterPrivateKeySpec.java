package crypto.ssa5.spec;

import java.math.BigInteger;

import matrix.ModularMatrix;

public class SAA5MasterPrivateKeySpec extends SAA5KeySpec {
	protected final BigInteger c;
	protected final ModularMatrix[] A;
	protected final ModularMatrix xB;
	protected final ModularMatrix NB;

	public SAA5MasterPrivateKeySpec(SAA5ParameterSpec params, BigInteger c, ModularMatrix[] A, ModularMatrix xB,
			ModularMatrix NBinverse) {
		super(params);
		this.c = c;
		this.A = A;
		this.xB = xB;
		this.NB = NBinverse;
	}

	public ModularMatrix getXB() {
		return xB;
	}

	public ModularMatrix getNB() {
		return NB;
	}
}
