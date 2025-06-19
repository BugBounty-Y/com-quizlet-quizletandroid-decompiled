package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class P5 {
    public static final P5 b = new P5(new C1815a[0]);
    public static final C1815a c;
    public final C1815a[] a;

    static {
        C1815a c1815a = new C1815a(-1, new int[0], new C2640t3[0], new long[0], new String[0]);
        int[] iArr = c1815a.d;
        int length = iArr.length;
        int iMax = Math.max(0, length);
        int[] iArrCopyOf = Arrays.copyOf(iArr, iMax);
        Arrays.fill(iArrCopyOf, length, iMax, 0);
        long[] jArr = c1815a.e;
        int length2 = jArr.length;
        int iMax2 = Math.max(0, length2);
        long[] jArrCopyOf = Arrays.copyOf(jArr, iMax2);
        Arrays.fill(jArrCopyOf, length2, iMax2, -9223372036854775807L);
        c = new C1815a(0, iArrCopyOf, (C2640t3[]) Arrays.copyOf(c1815a.c, 0), jArrCopyOf, (String[]) Arrays.copyOf(c1815a.f, 0));
        String str = Yo.a;
        Integer.toString(1, 36);
        Integer.toString(2, 36);
        Integer.toString(3, 36);
        Integer.toString(4, 36);
    }

    public P5(C1815a[] c1815aArr) {
        this.a = c1815aArr;
    }

    public final C1815a a(int i) {
        return i < 0 ? c : this.a[i];
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return obj != null && P5.class == obj.getClass() && Arrays.equals(this.a, ((P5) obj).a);
    }

    public final int hashCode() {
        return Arrays.hashCode(this.a) + (((int) (-9223372036854775807L)) * 961);
    }

    public final String toString() {
        return AbstractC0147y.d("AdPlaybackState(adsId=null, adResumePositionUs=0, adGroups=[", "])");
    }
}
