package com.google.android.gms.internal.ads;

import android.net.Uri;
import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.ads.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1815a {
    public final int a;
    public final Uri[] b;
    public final C2640t3[] c;
    public final int[] d;
    public final long[] e;
    public final String[] f;

    static {
        String str = Yo.a;
        Integer.toString(0, 36);
        Integer.toString(1, 36);
        Integer.toString(2, 36);
        Integer.toString(3, 36);
        Integer.toString(4, 36);
        Integer.toString(5, 36);
        Integer.toString(6, 36);
        Integer.toString(7, 36);
        Integer.toString(8, 36);
        Integer.toString(9, 36);
        Integer.toString(10, 36);
    }

    public C1815a(int i, int[] iArr, C2640t3[] c2640t3Arr, long[] jArr, String[] strArr) {
        Uri uri;
        int length = iArr.length;
        int length2 = c2640t3Arr.length;
        int i2 = 0;
        AbstractC1795We.B(length == length2);
        this.a = i;
        this.d = iArr;
        this.c = c2640t3Arr;
        this.e = jArr;
        this.b = new Uri[length2];
        while (true) {
            Uri[] uriArr = this.b;
            if (i2 >= uriArr.length) {
                this.f = strArr;
                return;
            }
            C2640t3 c2640t3 = c2640t3Arr[i2];
            if (c2640t3 == null) {
                uri = null;
            } else {
                V1 v1 = c2640t3.b;
                v1.getClass();
                uri = v1.a;
            }
            uriArr[i2] = uri;
            i2++;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C1815a.class == obj.getClass()) {
            C1815a c1815a = (C1815a) obj;
            if (this.a == c1815a.a && Arrays.equals(this.c, c1815a.c) && Arrays.equals(this.d, c1815a.d) && Arrays.equals(this.e, c1815a.e) && Arrays.equals(this.f, c1815a.f)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return (((Arrays.hashCode(this.e) + ((Arrays.hashCode(this.d) + ((Arrays.hashCode(this.c) + (((this.a * 31) - 1) * 961)) * 31)) * 31)) * 29791) + Arrays.hashCode(this.f)) * 31;
    }
}
