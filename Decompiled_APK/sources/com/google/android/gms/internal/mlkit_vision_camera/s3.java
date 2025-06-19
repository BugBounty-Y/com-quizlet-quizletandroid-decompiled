package com.google.android.gms.internal.mlkit_vision_camera;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class s3 {
    public static final long a(int i, int i2, coil3.size.h hVar, coil3.size.g gVar, coil3.size.h hVar2) {
        int i3;
        int i4;
        if (!Intrinsics.b(hVar, coil3.size.h.c)) {
            i = c(hVar.a, gVar);
            i2 = c(hVar.b, gVar);
        }
        coil3.size.c cVar = hVar2.a;
        if ((cVar instanceof coil3.size.a) && i != Integer.MIN_VALUE && i != Integer.MAX_VALUE && i > (i4 = ((coil3.size.a) cVar).a)) {
            i = i4;
        }
        coil3.size.c cVar2 = hVar2.b;
        if ((cVar2 instanceof coil3.size.a) && i2 != Integer.MIN_VALUE && i2 != Integer.MAX_VALUE && i2 > (i3 = ((coil3.size.a) cVar2).a)) {
            i2 = i3;
        }
        return (i2 & 4294967295L) | (i << 32);
    }

    public static final double b(int i, int i2, int i3, int i4, coil3.size.g gVar) {
        double d = i3 / i;
        double d2 = i4 / i2;
        int iOrdinal = gVar.ordinal();
        if (iOrdinal == 0) {
            return Math.max(d, d2);
        }
        if (iOrdinal == 1) {
            return Math.min(d, d2);
        }
        throw new NoWhenBranchMatchedException();
    }

    public static int c(coil3.size.c cVar, coil3.size.g gVar) {
        if (cVar instanceof coil3.size.a) {
            return ((coil3.size.a) cVar).a;
        }
        int iOrdinal = gVar.ordinal();
        if (iOrdinal == 0) {
            return Integer.MIN_VALUE;
        }
        if (iOrdinal == 1) {
            return SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        throw new NoWhenBranchMatchedException();
    }
}
