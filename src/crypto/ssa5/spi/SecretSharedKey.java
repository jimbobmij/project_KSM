package crypto.ssa5.spi;

import crypto.ssa5.interfaces.SAA5SecretKey;
import crypto.ssa5.spec.SAA5ParameterSpec;
import matrix.ModularMatrix;

public class SecretSharedKey implements SAA5SecretKey {
	private final SAA5ParameterSpec params;
	private final ModularMatrix key;

	SecretSharedKey(SAA5ParameterSpec params, ModularMatrix key) {
		this.params = params;
		this.key = key;
	}

	// Serialize
	@Override
	public byte[] toByteArray() {
		byte[] arrayParams = params.toByteArray();
		byte[] arrayKey = key.toByteArray();

		int length = arrayParams.length + arrayKey.length;
		byte[] res = new byte[length];

		int pos = 0;
		ByteArrayConverter.copyToArray(res, pos, arrayParams);

		pos += arrayParams.length;
		ByteArrayConverter.copyToArray(res, pos, arrayKey);

		return res;
	}

	@Override
	public int byteArrayLength() {
		return params.byteArrayLength() + key.byteArrayLength();
	}

	// Deserialize
	public SecretSharedKey(byte[] array) {
		int pos = 0;
		params = new SAA5ParameterSpec(array, pos);
		pos += params.byteArrayLength();
		key = new ModularMatrix(array, pos);
	}

	public final SAA5ParameterSpec getParams() {
		return params;
	}

	public final ModularMatrix getKey() {
		return key;
	}

	@Override
	public String getAlgorithm() {
		return "SAA5";
	}

	@Override
	public String getFormat() {
		return null;
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof SecretSharedKey))
			return false;
		SecretSharedKey other = (SecretSharedKey) obj;
		if (key == null) {
			if (other.key != null)
				return false;
		} else if (!key.equals(other.key))
			return false;
		if (params == null) {
			if (other.params != null)
				return false;
		} else if (!params.equals(other.params))
			return false;
		return true;
	}

}
