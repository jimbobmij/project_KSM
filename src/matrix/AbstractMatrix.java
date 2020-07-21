package matrix;

import java.util.Arrays;

public abstract class AbstractMatrix<M extends AbstractMatrix<M, E>, E extends Comparable<E>>
		implements Matrix<M, E>, Cloneable {
	protected final int rows;
	protected final int cols;
	protected final E[][] data;

	protected AbstractMatrix(int r, int c, E[][] d) {
		rows = r;
		cols = c;
		for (int i = 1; i < rows; i++)
			if (d[i].length != cols)
				throw new IllegalArgumentException("illegal array length in " + i + "th row.");
		data = d;
	}

	@Override
	public int getRowSize() {
		return rows;
	}

	@Override
	public int getColumnSize() {
		return cols;
	}

	protected final void checkIndex(int i, int j) {
		if (!(0 <= i && i < rows))
			throw new ArrayIndexOutOfBoundsException("rows size:" + rows + "(" + i + ")");
		if (!(0 <= j && j < cols))
			throw new ArrayIndexOutOfBoundsException("column size:" + cols + "(" + j + ")");
	}

	@Override
	public E get(int r, int c) {
		checkIndex(r, c);
		return data[r][c];
	}

	protected final void checkSquare() {
		int row = getRowSize();
		int col = getColumnSize();
		if (!(row == col))
			throw new ArrayIndexOutOfBoundsException("not square matrix(" + row + ", " + col + ")");
	}

	protected final void checkAdd(Matrix<?, ?> m) {
		int lrow = getRowSize();
		int lcol = getColumnSize();
		int rrow = m.getRowSize();
		int rcol = m.getColumnSize();

		if (!(lrow == rrow && lcol == rcol))
			throw new ArrayIndexOutOfBoundsException("L:(" + lrow + ", " + lcol + "), R:(" + rrow + ", " + rcol + ")");
	}

	protected final void checkMul(Matrix<?, ?> m) {
		int lcol = getColumnSize();
		int rrow = m.getRowSize();

		if (!(lcol == rrow))
			throw new ArrayIndexOutOfBoundsException(
					"L:(" + getRowSize() + "," + lcol + "), R:(" + rrow + "," + m.getColumnSize() + ")");
	}

	public final void print() {
		System.out.println(toString());
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof AbstractMatrix))
			return false;
		AbstractMatrix<?, ?> other = (AbstractMatrix<?, ?>) obj;
		if (rows != other.rows)
			return false;
		if (cols != other.cols)
			return false;
		if (!Arrays.deepEquals(data, other.data))
			return false;
		return true;
	}

	@Override
	public String toString() {
		String res = "\r\n";
		String s = "[";
		for (int i = 0; i < rows; i++) {
			for (int j = 0; j < cols; j++) {
				s = s.concat(data[i][j].toString());
				if (j < cols - 1)
					s += ", ";
				else if (i == rows - 1)
					s += "]";
			}
			res += s + "\r\n";
			s = " ";
		}
		return res;
	}
}
