package matrix;

@SuppressWarnings("serial")
public class NotSquareMatrixException extends RuntimeException {
	public NotSquareMatrixException(int row, int col) {
		super("row size (" + row + ") is not equals to col size (" + col + ")");
	}
}
