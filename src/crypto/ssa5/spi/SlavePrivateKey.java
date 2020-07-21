package crypto.ssa5.spi;

import java.util.Arrays;

import crypto.ssa5.interfaces.SAA5SlavePrivateKey;
import crypto.ssa5.spec.SAA5ParameterSpec;
import matrix.ModularMatrix;

public class SlavePrivateKey implements SAA5SlavePrivateKey {
	private static final long serialVersionUID = 3414514881901521860L;
	private final SAA5ParameterSpec params;
	private final ModularMatrix[] xA;

	SlavePrivateKey(SAA5ParameterSpec params, ModularMatrix[] xA) {
		this.params = params;
		this.xA = xA;
	}

	// Serialize
	@Override
	public byte[] toByteArray() {
		byte[] arrayParams = params.toByteArray();
		byte[] arrayXA = ByteArrayConverter.arrayToBytes(xA);

		int length = arrayParams.length + arrayXA.length;
		byte[] res = new byte[length];

		int pos = 0;
		ByteArrayConverter.copyToArray(res, pos, arrayParams);

		pos += arrayParams.length;
		ByteArrayConverter.copyToArray(res, pos, arrayXA);

		return res;
	}

	@Override
	public int byteArrayLength() {
		return params.byteArrayLength() + xA[0].byteArrayLength() * params.getI();
	}

	// Deserialize
	public SlavePrivateKey(byte[] array) {
		int pos = 0;
		params = new SAA5ParameterSpec(array, pos);
		int I = params.getI();
		pos += params.byteArrayLength();

		xA = new ModularMatrix[I];
		for (int i = 0; i < I; i++) {
			xA[i] = new ModularMatrix(array, pos);
			pos += xA[i].byteArrayLength();
		}
	}

	@Override
	public SAA5ParameterSpec getParams() {
		return params;
	}

	@Override
	public String getAlgorithm() {
		return "SAA5slave";
	}

	@Override
	public byte[] getEncoded() {
		return toByteArray();
	}

	@Override
	public String getFormat() {
		return null;
	}

	@Override
	public ModularMatrix[] getXA() {
		return xA;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof SlavePrivateKey))
			return false;
		SlavePrivateKey other = (SlavePrivateKey) obj;
		if (params == null) {
			if (other.params != null)
				return false;
		} else if (!params.equals(other.params))
			return false;
		if (!Arrays.equals(xA, other.xA))
			return false;
		return true;
	}
}
