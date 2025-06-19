package kotlin.text;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3320b;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class J {
    public static final boolean a(String str) {
        for (int i = 0; i < str.length(); i++) {
            char cCharAt = str.charAt(i);
            if (Intrinsics.g(cCharAt, 128) >= 0 || Character.isLetter(cCharAt)) {
                return true;
            }
        }
        return false;
    }

    public static final String b(long j) {
        return AbstractC3320b.d(CharsKt__CharJVMKt.checkRadix(10), j);
    }

    public static final String c(int i) {
        return AbstractC3320b.d(CharsKt__CharJVMKt.checkRadix(16), i & 4294967295L);
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0024  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final byte d(java.lang.String r3) {
        /*
            java.lang.String r0 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r0)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r0)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r0)
            kotlin.A r0 = f(r3)
            r1 = 0
            if (r0 == 0) goto L24
            r2 = 255(0xff, float:3.57E-43)
            int r0 = r0.a
            int r2 = java.lang.Integer.compareUnsigned(r0, r2)
            if (r2 <= 0) goto L1d
            goto L24
        L1d:
            byte r0 = (byte) r0
            kotlin.x r2 = new kotlin.x
            r2.<init>(r0)
            goto L25
        L24:
            r2 = r1
        L25:
            if (r2 == 0) goto L2a
            byte r3 = r2.a
            return r3
        L2a:
            kotlin.text.StringsKt__StringNumberConversionsKt.g(r3)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.text.J.d(java.lang.String):byte");
    }

    public static final int e(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(str, "<this>");
        kotlin.A aF = f(str);
        if (aF != null) {
            return aF.a;
        }
        StringsKt__StringNumberConversionsKt.g(str);
        throw null;
    }

    public static final kotlin.A f(String str) {
        int i;
        Intrinsics.checkNotNullParameter(str, "<this>");
        CharsKt__CharJVMKt.checkRadix(10);
        int length = str.length();
        if (length == 0) {
            return null;
        }
        int i2 = 0;
        char cCharAt = str.charAt(0);
        if (Intrinsics.g(cCharAt, 48) >= 0) {
            i = 0;
        } else {
            if (length == 1 || cCharAt != '+') {
                return null;
            }
            i = 1;
        }
        kotlin.z zVar = kotlin.A.b;
        int iDivideUnsigned = 119304647;
        while (i < length) {
            int iDigit = Character.digit((int) str.charAt(i), 10);
            if (iDigit < 0) {
                return null;
            }
            if (Integer.compareUnsigned(i2, iDivideUnsigned) > 0) {
                if (iDivideUnsigned != 119304647) {
                    return null;
                }
                iDivideUnsigned = Integer.divideUnsigned(-1, 10);
                if (Integer.compareUnsigned(i2, iDivideUnsigned) > 0) {
                    return null;
                }
            }
            int i3 = i2 * 10;
            int i4 = iDigit + i3;
            if (Integer.compareUnsigned(i4, i3) < 0) {
                return null;
            }
            i++;
            i2 = i4;
        }
        return new kotlin.A(i2);
    }

    public static final long g(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        kotlin.D dH = h(str);
        if (dH != null) {
            return dH.a;
        }
        StringsKt__StringNumberConversionsKt.g(str);
        throw null;
    }

    public static final kotlin.D h(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(str, "<this>");
        CharsKt__CharJVMKt.checkRadix(10);
        int length = str.length();
        if (length == 0) {
            return null;
        }
        int i = 0;
        char cCharAt = str.charAt(0);
        if (Intrinsics.g(cCharAt, 48) < 0) {
            if (length == 1 || cCharAt != '+') {
                return null;
            }
            i = 1;
        }
        long j = 10;
        kotlin.C c = kotlin.D.b;
        long j2 = 0;
        long jDivideUnsigned = 512409557603043100L;
        while (i < length) {
            int iDigit = Character.digit((int) str.charAt(i), 10);
            if (iDigit < 0) {
                return null;
            }
            if (Long.compareUnsigned(j2, jDivideUnsigned) > 0) {
                if (jDivideUnsigned != 512409557603043100L) {
                    return null;
                }
                jDivideUnsigned = Long.divideUnsigned(-1L, j);
                if (Long.compareUnsigned(j2, jDivideUnsigned) > 0) {
                    return null;
                }
            }
            long j3 = j2 * j;
            kotlin.z zVar = kotlin.A.b;
            long j4 = (iDigit & 4294967295L) + j3;
            if (Long.compareUnsigned(j4, j3) < 0) {
                return null;
            }
            i++;
            j2 = j4;
        }
        return new kotlin.D(j2);
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0025  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final short i(java.lang.String r3) {
        /*
            java.lang.String r0 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r0)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r0)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r0)
            kotlin.A r0 = f(r3)
            r1 = 0
            if (r0 == 0) goto L25
            r2 = 65535(0xffff, float:9.1834E-41)
            int r0 = r0.a
            int r2 = java.lang.Integer.compareUnsigned(r0, r2)
            if (r2 <= 0) goto L1e
            goto L25
        L1e:
            short r0 = (short) r0
            kotlin.H r2 = new kotlin.H
            r2.<init>(r0)
            goto L26
        L25:
            r2 = r1
        L26:
            if (r2 == 0) goto L2b
            short r3 = r2.a
            return r3
        L2b:
            kotlin.text.StringsKt__StringNumberConversionsKt.g(r3)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.text.J.i(java.lang.String):short");
    }
}
