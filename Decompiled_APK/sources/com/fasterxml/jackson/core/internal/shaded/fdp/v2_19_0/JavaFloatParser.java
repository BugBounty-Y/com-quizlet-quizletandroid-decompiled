package com.fasterxml.jackson.core.internal.shaded.fdp.v2_19_0;

/* loaded from: classes.dex */
public abstract class JavaFloatParser {
    private static final JavaFloatBitsFromByteArray BYTE_ARRAY_PARSER = new JavaFloatBitsFromByteArray();
    private static final JavaFloatBitsFromCharArray CHAR_ARRAY_PARSER = new JavaFloatBitsFromCharArray();
    private static final JavaFloatBitsFromCharSequence CHAR_SEQUENCE_PARSER = new JavaFloatBitsFromCharSequence();

    public static float parseFloat(CharSequence charSequence) throws NumberFormatException {
        return parseFloat(charSequence, 0, charSequence.length());
    }

    public static float parseFloat(CharSequence charSequence, int i, int i2) throws NumberFormatException {
        return Float.intBitsToFloat((int) CHAR_SEQUENCE_PARSER.parseFloatingPointLiteral(charSequence, i, i2));
    }

    public static float parseFloat(char[] cArr, int i, int i2) throws NumberFormatException {
        return Float.intBitsToFloat((int) CHAR_ARRAY_PARSER.parseFloatingPointLiteral(cArr, i, i2));
    }
}
