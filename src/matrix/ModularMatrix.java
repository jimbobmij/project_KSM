package matrix;

import java.math.BigInteger;
import java.util.Arrays;

import crypto.ssa5.interfaces.Serializable;
import crypto.ssa5.spi.ByteArrayConverter;
import matrix.NotInvertibleException;

public class ModularMatrix extends AbstractMatrix<ModularMatrix, BigInteger> implements Serializable {
	private static final long serialVersionUID = 5248461084963693155L;
	private final BigInteger modulus;

	public ModularMatrix(BigInteger[][] d, BigInteger mod) {
		super(d.length, d[0].length, d);
		if (mod.compareTo(new BigInteger("2")) < 0)
			throw new IllegalArgumentException("mod must be greater than 2.");

		for (int i = 0; i < rows; i++)
			for (int j = 0; j < cols; j++)
				data[i][j] = data[i][j].mod(mod);
		modulus = mod;
	}

	// Serialize
	// [0] = d (1 bytes)
	// [1 : 2] = mL(mod length) (2 bytes)
	// [3 : 2 + mL] = mod (m' bytes)
	// [3 + mL : 2 + 2 * mL] = 1st(1,1) elem (m' bytes)
	// [3 + 2 * mL : 2 + 3 * mL] = 2nd(1,2) elem (m' bytes)
	// ...
	public static int POS_DIM = 0;
	public static int POS_MOD_BYTES = 1;
	public static int POS_MOD = 3;

	@Override
	public final byte[] toByteArray() {
		byte mL = (byte) (((modulus.bitLength() + 1) + 7) / 8);
		byte[] res = new byte[byteArrayLength()];

		ByteArrayConverter.saveByte(res, POS_DIM, rows);
		ByteArrayConverter.saveShort(res, POS_MOD_BYTES, mL);
		ByteArrayConverter.saveBInt(res, POS_MOD, modulus, mL);

		int posElem = POS_MOD + mL;
		for (int e = 0; e < rows * cols; e++)
			ByteArrayConverter.saveBInt(res, posElem + (e * mL), data[e / rows][e % cols], mL);
		return res;
	}

	@Override
	public int byteArrayLength() {
		byte mL = (byte) (((modulus.bitLength() + 1) + 7) / 8);
		return POS_MOD + mL + (mL * (rows * cols));
	}

	public final byte[] toKeyByteArray() {
		int mL = ((modulus.bitLength() + 1) + 7) / 8;
		int keyLength = mL * rows * cols;
		byte[] res = new byte[keyLength];
		int pos = 0;
		for (int e = 0; e < rows * cols; e++)
			ByteArrayConverter.saveBInt(res, pos + (e * mL), data[e / rows][e % cols], mL);
		return res;
	}

	// Deserialize
	public ModularMatrix(byte[] array, int pos) {
		super(getD(array, pos), getD(array, pos), new BigInteger[getD(array, pos)][getD(array, pos)]);
		modulus = getM(array, pos);
		for (int e = 0; e < rows * cols; e++)
			data[e / rows][e % cols] = getElem(array, pos, e / rows, e % cols);
	}

	public ModularMatrix(byte[] array) {
		this(array, 0);
	}

	private static int getD(byte[] array, int pos) {
		return ByteArrayConverter.loadByte(array, pos + POS_DIM);
	}

	private static int getML(byte[] array, int pos) {
		return ByteArrayConverter.loadShort(array, pos + POS_MOD_BYTES);
	}

	private static BigInteger getM(byte[] array, int pos) {
		return ByteArrayConverter.loadBInt(array, pos + POS_MOD, getML(array, pos));
	}

	private static BigInteger getElem(byte[] array, int pos, int r, int c) {
		int dim = getD(array, pos);
		int mL = getML(array, pos);
		int POS_ELEM = POS_MOD + mL;
		return ByteArrayConverter.loadBInt(array, pos + POS_ELEM + (((r * dim) + c) * mL), mL);
	}

	public BigInteger getModulus() {
		return modulus;
	}

	@Override
	public BigInteger[] getRow(int r) {
		checkIndex(r, 0);
		return data[r];
	}

	@Override
	public BigInteger[] getColumn(int c) {
		checkIndex(0, c);
		BigInteger[] res = new BigInteger[cols];
		for (int i = 0; i < cols; i++)
			res[i] = data[i][c];
		return res;
	}

	@Override
	public ModularMatrix zero(int rows, int columns) {
		if (rows <= 0)
			throw new IllegalArgumentException("\'rows\' must be positive.(" + rows + ")");
		if (columns <= 0)
			throw new IllegalArgumentException("\'rows\' must be positive.(" + rows + ")");

		BigInteger[][] res = new BigInteger[rows][columns];

		for (int i = 0; i < rows; i++)
			for (int j = 0; j < columns; j++)
				res[i][j] = BigInteger.ZERO;
		return new ModularMatrix(res, modulus);
	}

	@Override
	public ModularMatrix diag(BigInteger val, int dim) {
		if (dim <= 0)
			throw new IllegalArgumentException("\'dim\' must be positive.(" + dim + ")");
		BigInteger[][] res = new BigInteger[dim][dim];

		for (int i = 0; i < dim; i++)
			for (int j = 0; j < dim; j++)
				res[i][j] = (i == j) ? val : BigInteger.ZERO;
		return new ModularMatrix(res, modulus);
	}

	@Override
	public ModularMatrix idm(int dim) {
		return diag(BigInteger.ONE, dim);
	}

	@Override
	public ModularMatrix set(int r, int c, BigInteger val) {
		checkIndex(r, c);
		BigInteger[][] res = cloneData();
		res[r][c] = val.mod(modulus);
		return new ModularMatrix(res, modulus);
	}

	@Override
	public BigInteger get(int r, int c) {
		return data[r][c];
	}

	protected final void checkMod(ModularMatrix mat) {
		if (!modulus.equals(mat.modulus))
			throw new RuntimeException("modulus is different " + modulus + ", " + mat.modulus);
	}

	public static ModularMatrix idm(int dim, BigInteger modulus) {
		BigInteger[][] res = new BigInteger[dim][dim];
		for (int i = 0; i < dim; i++)
			for (int j = 0; j < dim; j++)
				if (i == j)
					res[i][j] = BigInteger.ONE;
				else
					res[i][j] = BigInteger.ZERO;
		return new ModularMatrix(res, modulus);
	}

	@Override
	public ModularMatrix scalar(BigInteger scalar) {
		BigInteger[][] res = new BigInteger[rows][cols];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < cols; j++)
				res[i][j] = get(i, j).multiply(scalar).mod(modulus);
		return new ModularMatrix(res, modulus);
	}

	public ModularMatrix add(ModularMatrix mat, BigInteger mod) {
		checkAdd(mat);
		BigInteger[][] res = new BigInteger[rows][cols];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < cols; j++)
				res[i][j] = get(i, j).add(mat.get(i, j).mod(mod));
		return new ModularMatrix(res, mod);
	}

	@Override
	public ModularMatrix add(ModularMatrix mat) {
		checkMod(mat);
		return add(mat, modulus);
	}

	public ModularMatrix sub(ModularMatrix mat, BigInteger mod) {
		checkAdd(mat);
		BigInteger[][] res = new BigInteger[rows][cols];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < cols; j++)
				res[i][j] = get(i, j).subtract((mat.get(i, j)).mod(mod));
		return new ModularMatrix(res, mod);
	}

	@Override
	public ModularMatrix sub(ModularMatrix mat) {
		checkMod(mat);
		return sub(mat, modulus);
	}

	public ModularMatrix multi(ModularMatrix mat, BigInteger mod) {
		checkMul(mat);
		BigInteger[][] res = new BigInteger[rows][mat.cols];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < mat.cols; j++) {
				BigInteger v = BigInteger.ZERO;
				for (int k = 0; k < cols; k++)
					v = v.add(data[i][k].multiply(mat.data[k][j]));
				res[i][j] = v.mod(mod);
			}
		return new ModularMatrix(res, mod);
	}

	@Override
	public ModularMatrix multi(ModularMatrix mat) {
		checkMod(mat);
		return multi(mat, modulus);
	}

	@Override
	public ModularMatrix pow(int exponent) throws NotInvertibleException {
		checkSquare();

		if (exponent == 0)
			return idm(rows);

		ModularMatrix res = this;

		if (exponent < 0) {
			res = res.inverse();
			exponent = -exponent;
		}

		for (int i = 1; i < exponent; i++)
			res = res.multi(this);

		return res;
	}

	@Override
	public ModularMatrix schurExp(BigInteger base) {
		return schurExp(base, modulus);
	}

	public ModularMatrix schurExp(BigInteger base, BigInteger mod) {
		BigInteger[][] res = new BigInteger[rows][cols];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < cols; j++)
				res[i][j] = schurExp(base, get(i, j), mod);
		return new ModularMatrix(res, mod);
	}

	@Override
	public ModularMatrix schurExp(ModularMatrix mat) {
		return schurExp(mat, modulus);
	}

	public ModularMatrix schurExp(ModularMatrix mat, BigInteger mod) {
		checkAdd(mat);
		BigInteger[][] res = new BigInteger[rows][cols];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < cols; j++)
				res[i][j] = schurExp(get(i, j), mat.get(i, j), mod);
		return new ModularMatrix(res, mod);
	}

	static BigInteger schurExp(BigInteger base, BigInteger exponent, BigInteger mod) {
		if (base.equals(BigInteger.ZERO))
			return BigInteger.ZERO;
		else
			return base.modPow(exponent, mod);
	}

	/**
	 * return a modular matrix M : M[i][j] =
	 * Π<sub>k</sub>(this[i][k]<sup>mat[k][j]</sup>)
	 */
	public ModularMatrix exponent(ModularMatrix m, BigInteger mod) {
		checkMul(m);
		BigInteger[][] res = new BigInteger[rows][m.cols];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < m.cols; j++) {
				BigInteger v = BigInteger.ONE;
				for (int k = 0; k < cols; k++)
					v = v.multiply(schurExp(data[i][k], m.data[k][j], mod));
				res[i][j] = v;
			}
		return new ModularMatrix(res, mod);
	}

	/**
	 * return a modular matrix M : M[i][j] =
	 * Π<sub>k</sub>(this[k][j]<sup>m[i][k]</sup>)
	 */
	public ModularMatrix exponentReversely(ModularMatrix m, BigInteger mod) {
		checkMul(m);
		BigInteger[][] res = new BigInteger[rows][m.cols];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < m.cols; j++) {
				BigInteger v = BigInteger.ONE;
				for (int k = 0; k < cols; k++)
					v = v.multiply(schurExp(data[k][j], m.data[i][k], mod));
				res[i][j] = v;
			}
		return new ModularMatrix(res, mod);
	}

	public BigInteger[][] cloneData() {
		BigInteger[][] res = new BigInteger[rows][cols];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < cols; j++)
				res[i][j] = data[i][j];
		return res;
	}

	@Override
	public ModularMatrix exchangeRow(int i, int j) {
		checkIndex(i, cols);
		checkIndex(j, cols);
		BigInteger[][] res = cloneData();
		for (int k = 0; k < cols; k++) {
			res[i][k] = get(j, k);
			res[j][k] = get(i, k);
		}
		return new ModularMatrix(res, modulus);
	}

	@Override
	public ModularMatrix exchangeCol(int i, int j) {
		checkIndex(rows, i);
		checkIndex(rows, j);
		BigInteger[][] res = cloneData();
		for (int k = 0; k < cols; k++) {
			res[k][i] = get(k, j);
			res[k][j] = get(k, i);
		}
		return new ModularMatrix(res, modulus);
	}

	@Override
	public ModularMatrix transpose() {
		BigInteger[][] res = new BigInteger[cols][rows];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < cols; j++)
				res[i][j] = data[j][i];
		return new ModularMatrix(res, modulus);
	}

	@Override
	public ModularMatrix subMatrix(int r, int c) {
		checkIndex(r, c);
		BigInteger[][] d = new BigInteger[rows - 1][cols - 1];
		for (int i = 0; i < rows - 1; i++)
			for (int j = 0; j < cols - 1; j++)
				if (i < r) {
					if (j < c)
						d[i][j] = get(i, j);
					else
						d[i][j] = get(i, j + 1);
				} else {
					if (j < c)
						d[i][j] = get(i + 1, j);
					else
						d[i][j] = get(i + 1, j + 1);
				}
		return new ModularMatrix(d, modulus);
	}

	private BigInteger sign(int r, int c) {
		if (((r + c) & 1) == 0)
			return BigInteger.ONE;
		else
			return BigInteger.ONE.negate();
	}

	@Override
	public BigInteger det() {
		checkSquare();
		return subDet();
	}

	private BigInteger subDet() {
		if (rows == 1 && cols == 1)
			return get(0, 0);
		else {
			BigInteger sc = BigInteger.ZERO;
			for (int i = 0; i < rows; i++)
				// (-1)^(i+0) * a_i0 * det(A'i0)
				sc = sc.add(sign(i, 0).multiply(get(i, 0).multiply(subMatrix(i, 0).subDet())));
			return sc;
		}
	}

	@Override
	public BigInteger cofactor(int r, int c) {
		return sign(r, c).multiply(subMatrix(r, c).det());
	}

	@Override
	public ModularMatrix inverse() throws NotInvertibleException {
		checkSquare();
		BigInteger[][] res = new BigInteger[rows][cols];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < cols; j++)
				res[i][j] = cofactor(j, i);
		return new ModularMatrix(res, modulus).scalar(det().modInverse(modulus));
	}

	public ModularMatrix changeMod(BigInteger mod) {
		BigInteger[][] res = new BigInteger[rows][cols];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < cols; j++)
				res[i][j] = data[i][j].mod(mod);
		return new ModularMatrix(res, mod);
	}

	@Override
	public ModularMatrix clone() {
		return new ModularMatrix(this.cloneData(), this.getModulus());
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof ModularMatrix))
			return false;
		ModularMatrix other = (ModularMatrix) obj;
		if (rows != other.rows)
			return false;
		if (cols != other.cols)
			return false;
		if (!Arrays.deepEquals(data, other.data))
			return false;
		return true;
	}

}
