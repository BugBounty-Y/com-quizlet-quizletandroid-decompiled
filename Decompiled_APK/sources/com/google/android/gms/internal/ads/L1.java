package com.google.android.gms.internal.ads;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class L1 {
    public final I1 a;
    public final int b;
    public final long[] c;
    public final int[] d;
    public final int e;
    public final long[] f;
    public final int[] g;
    public final long h;

    public L1(I1 i1, long[] jArr, int[] iArr, int i, long[] jArr2, int[] iArr2, long j) {
        int length = iArr.length;
        int length2 = jArr2.length;
        AbstractC1795We.B(length == length2);
        int length3 = jArr.length;
        AbstractC1795We.B(length3 == length2);
        int length4 = iArr2.length;
        AbstractC1795We.B(length4 == length2);
        this.a = i1;
        this.c = jArr;
        this.d = iArr;
        this.e = i;
        this.f = jArr2;
        this.g = iArr2;
        this.h = j;
        this.b = length3;
        if (length4 > 0) {
            int i2 = length4 - 1;
            iArr2[i2] = iArr2[i2] | 536870912;
        }
    }

    public final int a(long j) {
        int i;
        String str = Yo.a;
        long[] jArr = this.f;
        int iBinarySearch = Arrays.binarySearch(jArr, j);
        if (iBinarySearch < 0) {
            i = ~iBinarySearch;
        } else {
            while (true) {
                int i2 = iBinarySearch + 1;
                if (i2 >= jArr.length || jArr[i2] != j) {
                    break;
                }
                iBinarySearch = i2;
            }
            i = iBinarySearch;
        }
        while (i < jArr.length) {
            if ((this.g[i] & 1) != 0) {
                return i;
            }
            i++;
        }
        return -1;
    }
}
