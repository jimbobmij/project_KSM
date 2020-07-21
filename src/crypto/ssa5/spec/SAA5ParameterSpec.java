package crypto.ssa5.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

import crypto.ssa5.interfaces.Serializable;
import crypto.ssa5.spi.ByteArrayConverter;

public class SAA5ParameterSpec implements AlgorithmParameterSpec, Serializable {
	protected final int d;
	protected final BigInteger p;
	protected final int I;

	public SAA5ParameterSpec(int dim, BigInteger mod, int keyLength) {
		if (dim < 0)
			throw new IllegalArgumentException("parameter \"dim\" must be positive.");
		d = dim;

		if (mod.compareTo(new BigInteger("2")) < 0)
			throw new IllegalArgumentException("parameter \"mod\" must be greater than or equal to 2.");
		p = mod;

		if (keyLength < 0)
			throw new IllegalArgumentException("parameter \"sKeySize\" must be positive.");
		I = keyLength;
	}

	// Serialize
	// [0] = d (1 bytes)
	// [1 : 2] = I (2 bytes)
	// [3 : 4] = p'(p length) (2 bytes)
	// [5 : 4 + pL] = p (p' bytes)
	public static int POS_D = 0;
	public static int POS_I = 1;
	public static int POS_P_BYTES = 3;
	public static int POS_P = 5;

	@Override
	public final byte[] toByteArray() {
		byte[] res = new byte[byteArrayLength()];

		ByteArrayConverter.saveByte(res, POS_D, d);
		ByteArrayConverter.saveShort(res, POS_I, I);
		int pL = ByteArrayConverter.byteLength(p.bitLength());
		ByteArrayConverter.saveShort(res, POS_P_BYTES, pL);
		ByteArrayConverter.saveBInt(res, POS_P, p, pL);
		return res;
	}

	@Override
	public int byteArrayLength() {
		int pL = ByteArrayConverter.byteLength(p.bitLength());
		return POS_P + pL;
	}

	// Deserialize
	public SAA5ParameterSpec(byte[] array, int pos) {
		d = getD(array, pos);
		I = getI(array, pos);
		p = getP(array, pos);
	}

	public SAA5ParameterSpec(byte[] array) {
		this(array, 0);
	}

	private static int getD(byte[] array, int pos) {
		return ByteArrayConverter.loadByte(array, pos + POS_D);
	}

	private static int getI(byte[] array, int pos) {
		return ByteArrayConverter.loadShort(array, pos + POS_I);
	}

	private static int getPL(byte[] array, int pos) {
		return ByteArrayConverter.loadShort(array, pos + POS_P_BYTES);
	}

	private static BigInteger getP(byte[] array, int pos) {
		return ByteArrayConverter.loadBInt(array, pos + POS_P, getPL(array, pos));
	}

	public final int getD() {
		return d;
	}

	public final BigInteger getP() {
		return p;
	}

	public final int getI() {
		return I;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof SAA5ParameterSpec))
			return false;
		SAA5ParameterSpec other = (SAA5ParameterSpec) obj;
		if (I != other.I)
			return false;
		if (d != other.d)
			return false;
		if (p == null) {
			if (other.p != null)
				return false;
		} else if (!p.equals(other.p))
			return false;
		return true;
	}
}
