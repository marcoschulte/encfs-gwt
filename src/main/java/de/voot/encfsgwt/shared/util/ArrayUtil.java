package de.voot.encfsgwt.shared.util;

public class ArrayUtil {

	/**
	 * Same functionality as {@link Arrays.copyOfRange}.
	 * 
	 * @param original
	 * @param from
	 * @param to
	 * @return
	 */
	public static byte[] copyOfRange(byte[] original, int from, int to) {
		int newLength = to - from;
		if (newLength < 0)
			throw new IllegalArgumentException(from + " > " + to);
		byte[] copy = new byte[newLength];
		System.arraycopy(original, from, copy, 0, Math.min(original.length - from, newLength));
		return copy;
	}

	/**
	 * Same functionality as {@link Arrays.copyOf}
	 * 
	 * @param original
	 * @param newLength
	 * @return
	 */
	public static byte[] copyOf(byte[] original, int newLength) {
		byte[] copy = new byte[newLength];
		System.arraycopy(original, 0, copy, 0, Math.min(original.length, newLength));
		return copy;
	}

	public static byte[] clone(byte[] original) {
		return copyOf(original, original.length);
	}

	public static char[] copyOf(char[] original, int newLength) {
		char[] copy = new char[newLength];
		System.arraycopy(original, 0, copy, 0, Math.min(original.length, newLength));
		return copy;
	}

	public static char[] clone(char[] original) {
		return copyOf(original, original.length);
	}

}
