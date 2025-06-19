package org.apache.commons.lang3.builder;

import java.lang.reflect.Array;

/* loaded from: classes3.dex */
public final class b {
    public final int a;
    public int b;

    static {
        new ThreadLocal();
    }

    public b() {
        this.a = 37;
        this.b = 17;
    }

    public final void a(long j) {
        this.b = (this.b * this.a) + ((int) (j ^ (j >> 32)));
    }

    public final void b(Object obj) {
        int i = this.a;
        if (obj == null) {
            this.b *= i;
            return;
        }
        if (!obj.getClass().isArray()) {
            this.b = obj.hashCode() + (this.b * i);
            return;
        }
        int i2 = 0;
        if (obj instanceof long[]) {
            long[] jArr = (long[]) obj;
            int length = jArr.length;
            while (i2 < length) {
                a(jArr[i2]);
                i2++;
            }
            return;
        }
        if (obj instanceof int[]) {
            int[] iArr = (int[]) obj;
            int length2 = iArr.length;
            while (i2 < length2) {
                this.b = (this.b * i) + iArr[i2];
                i2++;
            }
            return;
        }
        if (obj instanceof short[]) {
            short[] sArr = (short[]) obj;
            int length3 = sArr.length;
            while (i2 < length3) {
                this.b = (this.b * i) + sArr[i2];
                i2++;
            }
            return;
        }
        if (obj instanceof char[]) {
            char[] cArr = (char[]) obj;
            int length4 = cArr.length;
            while (i2 < length4) {
                this.b = (this.b * i) + cArr[i2];
                i2++;
            }
            return;
        }
        if (obj instanceof byte[]) {
            byte[] bArr = (byte[]) obj;
            int length5 = bArr.length;
            while (i2 < length5) {
                this.b = (this.b * i) + bArr[i2];
                i2++;
            }
            return;
        }
        if (obj instanceof double[]) {
            double[] dArr = (double[]) obj;
            int length6 = dArr.length;
            while (i2 < length6) {
                a(Double.doubleToLongBits(dArr[i2]));
                i2++;
            }
            return;
        }
        if (obj instanceof float[]) {
            float[] fArr = (float[]) obj;
            int length7 = fArr.length;
            while (i2 < length7) {
                this.b = Float.floatToIntBits(fArr[i2]) + (this.b * i);
                i2++;
            }
            return;
        }
        if (!(obj instanceof boolean[])) {
            Object[] objArr = (Object[]) obj;
            int length8 = objArr.length;
            while (i2 < length8) {
                b(objArr[i2]);
                i2++;
            }
            return;
        }
        boolean[] zArr = (boolean[]) obj;
        int length9 = zArr.length;
        while (i2 < length9) {
            this.b = (this.b * i) + (!zArr[i2] ? 1 : 0);
            i2++;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && this.b == ((b) obj).b;
    }

    public final int hashCode() {
        return this.b;
    }

    public b(int i, int i2) {
        Object[] objArr = new Object[0];
        if (!(i % 2 != 0)) {
            throw new IllegalArgumentException(Array.getLength(objArr) != 0 ? String.format("HashCodeBuilder requires an odd initial value", objArr) : "HashCodeBuilder requires an odd initial value");
        }
        Object[] objArr2 = new Object[0];
        if (!(i2 % 2 != 0)) {
            throw new IllegalArgumentException(Array.getLength(objArr2) != 0 ? String.format("HashCodeBuilder requires an odd multiplier", objArr2) : "HashCodeBuilder requires an odd multiplier");
        }
        this.a = i2;
        this.b = i;
    }
}
