package crypto.ssa5.spi;

import crypto.ssa5.interfaces.SAA5MasterPrivateKey;
import crypto.ssa5.spec.SAA5ParameterSpec;
import matrix.ModularMatrix;

public class MasterPrivateKey implements SAA5MasterPrivateKey {
	private static final long serialVersionUID = 8644841748581606978L;
	private final SAA5ParameterSpec params;
	private final ModularMatrix xB;
	private final ModularMatrix NB;

	MasterPrivateKey(SAA5ParameterSpec params, ModularMatrix NBinverse, ModularMatrix xB) {
		this.params = params;
		this.xB = xB;
		this.NB = NBinverse;
	}

	// Serialize
	@Override
	public byte[] toByteArray() {
		byte[] arrayParams = params.toByteArray();
		byte[] arrayXB = xB.toByteArray();
		byte[] arrayNB = NB.toByteArray();

		int length = arrayParams.length + arrayXB.length + arrayNB.length;
		byte[] res = new byte[length];

		int pos = 0;
		ByteArrayConverter.copyToArray(res, pos, arrayParams);

		pos += arrayParams.length;
		ByteArrayConverter.copyToArray(res, pos, arrayXB);

		pos += arrayXB.length;
		ByteArrayConverter.copyToArray(res, pos, arrayNB);

		return res;
	}

	@Override
	public int byteArrayLength() {
		return params.byteArrayLength() + xB.byteArrayLength() + NB.byteArrayLength();
	}

	// Deserialize
	MasterPrivateKey(byte[] array) {
		int pos = 0;
		params = new SAA5ParameterSpec(array, pos);
		pos += params.byteArrayLength();

		xB = new ModularMatrix(array, pos);
		pos += xB.byteArrayLength();

		NB = new ModularMatrix(array, pos);
		pos += NB.byteArrayLength();
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
	public ModularMatrix getXB() {
		return xB;
	}

	@Override
	public ModularMatrix getNB() {
		return NB;
	}

	@Override
	public SAA5ParameterSpec getParams() {
		return params;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof MasterPrivateKey))
			return false;
		MasterPrivateKey other = (MasterPrivateKey) obj;
		if (NB == null) {
			if (other.NB != null)
				return false;
		} else if (!NB.equals(other.NB))
			return false;
		if (params == null) {
			if (other.params != null)
				return false;
		} else if (!params.equals(other.params))
			return false;
		if (xB == null) {
			if (other.xB != null)
				return false;
		} else if (!xB.equals(other.xB))
			return false;
		return true;
	}

}
