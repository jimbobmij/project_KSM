package crypto.ssa5.spi;

import crypto.ssa5.interfaces.SAA5SlavePublicKey;
import crypto.ssa5.spec.SAA5ParameterSpec;
import matrix.ModularMatrix;

public class SlavePublicKey implements SAA5SlavePublicKey {
	private static final long serialVersionUID = 6088473120205620196L;
	private final SAA5ParameterSpec params;
	private final ModularMatrix yA;

	SlavePublicKey(SAA5ParameterSpec params, ModularMatrix yA) {
		this.params = params;
		this.yA = yA;
	}

	// Serialize
	@Override
	public byte[] toByteArray() {
		byte[] arrayParams = params.toByteArray();
		byte[] arrayYA = yA.toByteArray();

		int length = arrayParams.length + arrayYA.length;
		byte[] res = new byte[length];

		int pos = 0;
		ByteArrayConverter.copyToArray(res, pos, arrayParams);

		pos += arrayParams.length;
		ByteArrayConverter.copyToArray(res, pos, arrayYA);

		return res;
	}

	@Override
	public int byteArrayLength() {
		return params.byteArrayLength() + yA.byteArrayLength();
	}

	// Deserialize
	public SlavePublicKey(byte[] array) {
		int pos = 0;
		params = new SAA5ParameterSpec(array, pos);
		pos += params.byteArrayLength();
		yA = new ModularMatrix(array, pos);
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
	public ModularMatrix getYA() {
		return yA;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof SlavePublicKey))
			return false;
		SlavePublicKey other = (SlavePublicKey) obj;
		if (params == null) {
			if (other.params != null)
				return false;
		} else if (!params.equals(other.params))
			return false;
		if (yA == null) {
			if (other.yA != null)
				return false;
		} else if (!yA.equals(other.yA))
			return false;
		return true;
	}

}
