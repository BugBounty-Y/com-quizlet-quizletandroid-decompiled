package com.google.android.gms.internal.mlkit_vision_document_scanner;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.t, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3723t {
    public static final /* synthetic */ int a = 0;

    public static int a(float[] fArr, int[] iArr, byte[] bArr) {
        Arrays.fill(bArr, (byte) 0);
        int i = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        for (int i2 = 0; i2 < 6; i2++) {
            int iCeil = (int) Math.ceil(fArr[i2]);
            iArr[i2] = iCeil;
            if (i > iCeil) {
                Arrays.fill(bArr, (byte) 0);
                i = iCeil;
            }
            if (i == iCeil) {
                bArr[i2] = (byte) (bArr[i2] + 1);
            }
        }
        return i;
    }

    public static void b(char c) {
        String hexString = Integer.toHexString(c);
        throw new IllegalArgumentException("Illegal character: " + c + " (0x" + ("0000".substring(0, 4 - hexString.length()) + hexString) + ')');
    }

    public static boolean c(char c) {
        return c >= '0' && c <= '9';
    }

    public static boolean d(char c) {
        return c >= 128 && c <= 255;
    }

    public static boolean e(char c) {
        if (c == '\r' || c == '*' || c == '>' || c == ' ') {
            return true;
        }
        if (c < '0' || c > '9') {
            return c >= 'A' && c <= 'Z';
        }
        return true;
    }

    /* JADX WARN: Code restructure failed: missing block: B:107:0x01aa, code lost:
    
        return 4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x01af, code lost:
    
        return 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:113:0x01b4, code lost:
    
        return 3;
     */
    /* JADX WARN: Removed duplicated region for block: B:151:0x01f1 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:72:0x0123  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x012a  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0155  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x015d  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x016c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int f(java.lang.CharSequence r20, int r21, int r22) {
        /*
            Method dump skipped, instructions count: 507
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3723t.f(java.lang.CharSequence, int, int):int");
    }
}
