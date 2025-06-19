package com.facebook.appevents.ml;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public int[] a;
    public int b;
    public float[] c;

    public a(int[] shape) {
        Intrinsics.checkNotNullParameter(shape, "shape");
        this.a = shape;
        int iA = g.a(shape);
        this.b = iA;
        this.c = new float[iA];
    }
}
