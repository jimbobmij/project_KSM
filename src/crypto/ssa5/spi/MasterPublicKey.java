package crypto.ssa5.spi;

import java.util.Arrays;

import crypto.ssa5.interfaces.SAA5MasterPublicKey;
import crypto.ssa5.spec.SAA5ParameterSpec;
import matrix.ModularMatrix;

public class MasterPublicKey implements SAA5MasterPublicKey {
	private static final long serialVersionUID = -81651226894545181L;
	private final SAA5ParameterSpec params;
	private final ModularMatrix[] yB2;
	private final ModularMatrix[] yB3;

	public MasterPublicKey(SAA5ParameterSpec params, ModularMatrix[] yB2, ModularMatrix[] yB3) {
		this.params = params;
		this.yB2 = yB2;
		this.yB3 = yB3;
	}

	// Serialize
	@Override
	public byte[] toByteArray() {
		byte[] arrayParams = params.toByteArray();
		byte[] arrayYB2 = ByteArrayConverter.arrayToBytes(yB2);
		byte[] arrayYB3 = ByteArrayConverter.arrayToBytes(yB3);

		int length = arrayParams.length + arrayYB2.length + arrayYB3.length;
		byte[] res = new byte[length];

		int pos = 0;
		ByteArrayConverter.copyToArray(res, pos, arrayParams);

		pos += arrayParams.length;
		ByteArrayConverter.copyToArray(res, pos, arrayYB2);

		pos += arrayYB2.length;
		ByteArrayConverter.copyToArray(res, pos, arrayYB3);

		return res;
	}

	@Override
	public int byteArrayLength() {
		return params.byteArrayLength() + yB2[0].byteArrayLength() * (2 * params.getI());
	}

	// Deserialize
	public MasterPublicKey(byte[] array) {
		int pos = 0;
		params = new SAA5ParameterSpec(array, pos);
		int I = params.getI();
		pos += params.byteArrayLength();

		yB2 = new ModularMatrix[I];
		for (int i = 0; i < I; i++) {
			yB2[i] = new ModularMatrix(array, pos);
			pos += yB2[i].byteArrayLength();
		}

		yB3 = new ModularMatrix[I];
		for (int i = 0; i < I; i++) {
			yB3[i] = new ModularMatrix(array, pos);
			pos += yB3[i].byteArrayLength();
		}
	}

	@Override
	public String getAlgorithm() {
		return "SAA5master";
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
	public SAA5ParameterSpec getParams() {
		return params;
	}

	@Override
	public ModularMatrix[] getYB2() {
		return yB2.clone();
	}

	public ModularMatrix[] getYB3() {
		return yB3.clone();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof MasterPublicKey))
			return false;
		MasterPublicKey other = (MasterPublicKey) obj;
		if (params == null) {
			if (other.params != null)
				return false;
		} else if (!params.equals(other.params))
			return false;
		if (!Arrays.equals(yB2, other.yB2))
			return false;
		if (!Arrays.equals(yB3, other.yB3))
			return false;
		return true;
	}

}
