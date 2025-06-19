package androidx.collection;

import kotlin.collections.C4930v;

/* renamed from: androidx.collection.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0211i {
    public static final float[] a;

    static {
        long[] jArr = S.a;
        int iD = S.d(0);
        int iMax = iD > 0 ? Math.max(7, S.c(iD)) : 0;
        if (iMax != 0) {
            jArr = new long[((iMax + 15) & (-8)) >> 3];
            C4930v.q(jArr);
        }
        int i = iMax >> 3;
        long j = 255 << ((iMax & 7) << 3);
        jArr[i] = (jArr[i] & (~j)) | j;
        float[] fArr = new float[iMax];
        a = new float[0];
    }
}
