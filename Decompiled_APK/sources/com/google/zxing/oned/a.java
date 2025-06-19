package com.google.zxing.oned;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3731u;

/* loaded from: classes2.dex */
public abstract class a extends AbstractC3731u {
    public static final char[] b = "0123456789-$:/.+ABCD".toCharArray();
    public static final int[] c = {3, 6, 9, 96, 18, 66, 33, 36, 48, 72, 12, 24, 69, 81, 84, 21, 26, 41, 11, 14};

    public static boolean a(char[] cArr, char c2) {
        for (char c3 : cArr) {
            if (c3 == c2) {
                return true;
            }
        }
        return false;
    }
}
