package matrix;

public class IntegerMatrix extends AbstractMatrix<IntegerMatrix, Integer> {
	public IntegerMatrix(Integer[][] integer) {
		super(integer.length, integer[0].length, integer);
		for (int i = 1; i < rows; i++)
			if (integer[i].length != cols)
				throw new IllegalArgumentException("illegal array length in " + i + "th row.");
	}

	private Integer[][] cloneData() {
		Integer[][] res = new Integer[rows][cols];
		for (int i = 0; i < data.length; i++)
			for (int j = 0; j < data[0].length; j++)
				res[i][j] = data[i][j];
		return res;
	}

	@Override
	public IntegerMatrix clone() {
		return new IntegerMatrix(cloneData());
	}

	@Override
	public IntegerMatrix set(int r, int c, Integer val) {
		checkIndex(r, c);
		Integer[][] newData = cloneData();
		newData[r][c] = val;
		return new IntegerMatrix(newData);
	}

	@Override
	public Integer[] getRow(int r) {
		checkIndex(r, 0);
		return data[r];
	}

	@Override
	public Integer[] getColumn(int c) {
		checkIndex(0, c);
		Integer[] res = new Integer[cols];
		for (int i = 0; i < cols; i++)
			res[i] = data[i][c];
		return res;
	}

	@Override
	public IntegerMatrix zero(int rows, int columns) {
		if (rows <= 0)
			throw new IllegalArgumentException("\'rows\' must be positive.(" + rows + ")");
		if (columns <= 0)
			throw new IllegalArgumentException("\'rows\' must be positive.(" + rows + ")");

		Integer[][] newData = new Integer[rows][columns];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < columns; j++)
				newData[i][j] = 0;
		return new IntegerMatrix(newData);
	}

	@Override
	public IntegerMatrix diag(Integer val, int dim) {
		if (dim <= 0)
			throw new IllegalArgumentException("\'dim\' must be positive.(" + dim + ")");
		Integer[][] newData = new Integer[dim][dim];

		for (int i = 0; i < dim; i++)
			for (int j = 0; j < dim; j++)
				newData[i][j] = (i == j) ? val : 0;
		return new IntegerMatrix(newData);
	}

	@Override
	public IntegerMatrix idm(int dim) {
		return diag(1, dim);
	}

	@Override
	public IntegerMatrix add(IntegerMatrix mat) {
		checkAdd(mat);

		Integer[][] res = cloneData();
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < cols; j++)
				res[i][j] = get(i, j) + mat.get(i, j);

		return new IntegerMatrix(res);
	}

	@Override
	public IntegerMatrix sub(IntegerMatrix mat) {
		checkAdd(mat);

		Integer[][] res = cloneData();
		for (int i = 0; i < getRowSize(); i++)
			for (int j = 0; j < getColumnSize(); j++)
				res[i][j] = get(i, j) - mat.get(i, j);
		return new IntegerMatrix(res);

	}

	@Override
	public IntegerMatrix multi(IntegerMatrix mat) {
		checkMul(mat);

		Integer[][] res = new Integer[rows][mat.cols];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < mat.cols; j++) {
				Integer e = 0;
				for (int k = 0; k < cols; k++)
					e += get(i, k) * mat.get(k, j);
				res[i][j] = e;
			}
		return new IntegerMatrix(res);
	}

	@Override
	public IntegerMatrix scalar(Integer scalar) {
		Integer[][] res = cloneData();
		for (int i = 0; i < getRowSize(); i++)
			for (int j = 0; j < getColumnSize(); j++)
				res[i][j] = scalar * get(i, j);
		return new IntegerMatrix(res);
	}

	@Override
	public IntegerMatrix pow(int exponent) throws NotInvertibleException {
		checkSquare();

		if (exponent == 0)
			return idm(rows);

		IntegerMatrix res = this;

		if (exponent < 0) {
			res = res.inverse();
			exponent = -exponent;
		}

		for (int i = 1; i < exponent; i++)
			res = res.multi(this);

		return res;
	}

	@Override
	public IntegerMatrix schurExp(IntegerMatrix mat) {
		checkAdd(mat);

		Integer[][] res = new Integer[rows][cols];
		for (int i = 0; i < getRowSize(); i++)
			for (int j = 0; j < getColumnSize(); j++)
				res[i][j] = (int) Math.pow(get(i, j), mat.get(i, j));

		return new IntegerMatrix(res);
	}

	@Override
	public IntegerMatrix schurExp(Integer base) {
		Integer[][] res = new Integer[rows][cols];
		for (int i = 0; i < getRowSize(); i++)
			for (int j = 0; j < getColumnSize(); j++)
				res[i][j] = (int) Math.pow(base, get(i, j));

		return new IntegerMatrix(res);
	}

	@Override
	public IntegerMatrix exchangeRow(int i, int j) {
		checkIndex(i, cols);
		checkIndex(j, cols);
		Integer[][] res = cloneData();
		for (int k = 0; k < cols; k++) {
			res[i][k] = get(j, k);
			res[j][k] = get(i, k);
		}
		return new IntegerMatrix(res);
	}

	@Override
	public IntegerMatrix exchangeCol(int i, int j) {
		checkIndex(rows, i);
		checkIndex(rows, j);
		Integer[][] res = cloneData();
		for (int k = 0; k < cols; k++) {
			res[k][i] = get(k, j);
			res[k][j] = get(k, i);
		}
		return new IntegerMatrix(res);
	}

	@Override
	public IntegerMatrix transpose() {
		Integer[][] res = new Integer[cols][rows];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < cols; j++)
				res[i][j] = data[j][i];
		return new IntegerMatrix(res);
	}

	@Override
	public IntegerMatrix subMatrix(int r, int c) {
		checkIndex(r, c);
		Integer[][] res = new Integer[rows - 1][cols - 1];
		for (int i = 0; i < rows - 1; i++)
			for (int j = 0; j < cols - 1; j++)
				if (i < r) {
					if (j < c)
						res[i][j] = get(i, j);
					else
						res[i][j] = get(i, j + 1);
				} else {
					if (j < c)
						res[i][j] = get(i + 1, j);
					else
						res[i][j] = get(i + 1, j + 1);
				}
		return new IntegerMatrix(res);
	}

	// ------------------------------------------------------------
	// 複雑な行列操作
	private Integer sign(int r, int c) {
		if (((r + c) & 1) == 0)
			return 1;
		else
			return -1;
	}

	@Override
	public Integer det() {
		if (rows != cols)
			throw new ArithmeticException("rows A:" + rows + ",column A:" + cols);
		return subDet();
	}

	// 余因子展開
	private Integer subDet() {
		if (rows == 1 && cols == 1)
			return get(0, 0);
		else {
			Integer sc = 0;
			for (int i = 0; i < rows; i++)
				sc += sign(i, 0) * get(i, 0) * (subMatrix(i, 0).subDet());
			return sc;
		}
	}

	@Override
	public Integer cofactor(int r, int c) {
		return sign(r, c) * subMatrix(r, c).det();
	}

	@Override
	public IntegerMatrix inverse() throws NotInvertibleException {
		if (rows != cols)
			throw new ArithmeticException("正方行列ではありません");
		if (!(det() == 1))
			throw new NotInvertibleException();
		Integer[][] newData = new Integer[rows][cols];
		for (int i = 0; i < rows; i++)
			for (int j = 0; j < cols; j++)
				newData[i][j] = cofactor(j, i);
		return new IntegerMatrix(newData);
	}
}
