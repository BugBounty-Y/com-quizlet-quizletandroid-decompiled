package org.apache.commons.lang3.builder;

import java.util.ArrayList;

/* loaded from: classes3.dex */
public final class a {
    public boolean a = true;

    static {
        new ThreadLocal();
    }

    public a() {
        new ArrayList(1).add(String.class);
    }

    public final void a(Object obj, Object obj2) {
        boolean z;
        boolean z2;
        boolean z3;
        boolean z4;
        boolean z5;
        boolean z6;
        boolean z7;
        boolean z8;
        if (this.a && obj != obj2) {
            if (obj == null || obj2 == null) {
                this.a = false;
                return;
            }
            if (!obj.getClass().isArray()) {
                this.a = obj.equals(obj2);
                return;
            }
            if (obj.getClass() != obj2.getClass()) {
                this.a = false;
                return;
            }
            if (obj instanceof long[]) {
                long[] jArr = (long[]) obj;
                long[] jArr2 = (long[]) obj2;
                if (this.a && jArr != jArr2) {
                    if (jArr.length != jArr2.length) {
                        this.a = false;
                        return;
                    }
                    for (int i = 0; i < jArr.length && (z8 = this.a); i++) {
                        long j = jArr[i];
                        long j2 = jArr2[i];
                        if (z8) {
                            this.a = j == j2;
                        }
                    }
                    return;
                }
                return;
            }
            if (obj instanceof int[]) {
                int[] iArr = (int[]) obj;
                int[] iArr2 = (int[]) obj2;
                if (this.a && iArr != iArr2) {
                    if (iArr.length != iArr2.length) {
                        this.a = false;
                        return;
                    }
                    for (int i2 = 0; i2 < iArr.length && (z7 = this.a); i2++) {
                        int i3 = iArr[i2];
                        int i4 = iArr2[i2];
                        if (z7) {
                            this.a = i3 == i4;
                        }
                    }
                    return;
                }
                return;
            }
            if (obj instanceof short[]) {
                short[] sArr = (short[]) obj;
                short[] sArr2 = (short[]) obj2;
                if (this.a && sArr != sArr2) {
                    if (sArr.length != sArr2.length) {
                        this.a = false;
                        return;
                    }
                    for (int i5 = 0; i5 < sArr.length && (z6 = this.a); i5++) {
                        short s = sArr[i5];
                        short s2 = sArr2[i5];
                        if (z6) {
                            this.a = s == s2;
                        }
                    }
                    return;
                }
                return;
            }
            if (obj instanceof char[]) {
                char[] cArr = (char[]) obj;
                char[] cArr2 = (char[]) obj2;
                if (this.a && cArr != cArr2) {
                    if (cArr.length != cArr2.length) {
                        this.a = false;
                        return;
                    }
                    for (int i6 = 0; i6 < cArr.length && (z5 = this.a); i6++) {
                        char c = cArr[i6];
                        char c2 = cArr2[i6];
                        if (z5) {
                            this.a = c == c2;
                        }
                    }
                    return;
                }
                return;
            }
            if (obj instanceof byte[]) {
                byte[] bArr = (byte[]) obj;
                byte[] bArr2 = (byte[]) obj2;
                if (this.a && bArr != bArr2) {
                    if (bArr.length != bArr2.length) {
                        this.a = false;
                        return;
                    }
                    for (int i7 = 0; i7 < bArr.length && (z4 = this.a); i7++) {
                        byte b = bArr[i7];
                        byte b2 = bArr2[i7];
                        if (z4) {
                            this.a = b == b2;
                        }
                    }
                    return;
                }
                return;
            }
            if (obj instanceof double[]) {
                double[] dArr = (double[]) obj;
                double[] dArr2 = (double[]) obj2;
                if (this.a && dArr != dArr2) {
                    if (dArr.length != dArr2.length) {
                        this.a = false;
                        return;
                    }
                    for (int i8 = 0; i8 < dArr.length && (z3 = this.a); i8++) {
                        double d = dArr[i8];
                        double d2 = dArr2[i8];
                        if (z3) {
                            long jDoubleToLongBits = Double.doubleToLongBits(d);
                            long jDoubleToLongBits2 = Double.doubleToLongBits(d2);
                            if (this.a) {
                                this.a = jDoubleToLongBits == jDoubleToLongBits2;
                            }
                        }
                    }
                    return;
                }
                return;
            }
            if (obj instanceof float[]) {
                float[] fArr = (float[]) obj;
                float[] fArr2 = (float[]) obj2;
                if (this.a && fArr != fArr2) {
                    if (fArr.length != fArr2.length) {
                        this.a = false;
                        return;
                    }
                    for (int i9 = 0; i9 < fArr.length && (z2 = this.a); i9++) {
                        float f = fArr[i9];
                        float f2 = fArr2[i9];
                        if (z2) {
                            int iFloatToIntBits = Float.floatToIntBits(f);
                            int iFloatToIntBits2 = Float.floatToIntBits(f2);
                            if (this.a) {
                                this.a = iFloatToIntBits == iFloatToIntBits2;
                            }
                        }
                    }
                    return;
                }
                return;
            }
            if (!(obj instanceof boolean[])) {
                Object[] objArr = (Object[]) obj;
                Object[] objArr2 = (Object[]) obj2;
                if (this.a && objArr != objArr2) {
                    if (objArr.length != objArr2.length) {
                        this.a = false;
                        return;
                    }
                    for (int i10 = 0; i10 < objArr.length && this.a; i10++) {
                        a(objArr[i10], objArr2[i10]);
                    }
                    return;
                }
                return;
            }
            boolean[] zArr = (boolean[]) obj;
            boolean[] zArr2 = (boolean[]) obj2;
            if (this.a && zArr != zArr2) {
                if (zArr.length != zArr2.length) {
                    this.a = false;
                    return;
                }
                for (int i11 = 0; i11 < zArr.length && (z = this.a); i11++) {
                    boolean z9 = zArr[i11];
                    boolean z10 = zArr2[i11];
                    if (z) {
                        this.a = z9 == z10;
                    }
                }
            }
        }
    }
}
