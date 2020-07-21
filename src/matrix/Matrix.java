package matrix;

public interface Matrix<M extends Matrix<M, E>, E extends Comparable<E>> {
	M set(int r, int c, E e);

	E get(int r, int c);

	int getRowSize();

	int getColumnSize();

	E[] getRow(int r);

	E[] getColumn(int c);

	M zero(int rows, int columns);

	M idm(int dim);

	M diag(E val, int dim);

	M exchangeCol(int i, int j);

	M exchangeRow(int i, int j);

	M transpose();

	M subMatrix(int r, int c);

	E cofactor(int r, int c);

	E det();

	M inverse();

	M scalar(E scalar);

	M add(M mat);

	M sub(M mat);

	M multi(M mat);

	M pow(int exponent) throws NotInvertibleException;

	M schurExp(E base);

	M schurExp(M mat);

}
