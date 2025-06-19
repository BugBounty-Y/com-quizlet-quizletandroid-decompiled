package com.airbnb.lottie.model;

import android.graphics.PointF;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class b {
    public String a;
    public String b;
    public float c;
    public int d;
    public int e;
    public float f;
    public float g;
    public int h;
    public int i;
    public float j;
    public boolean k;
    public PointF l;
    public PointF m;

    public final int hashCode() {
        int iK = ((AbstractC0147y.k(this.d) + (((int) (d0.e(this.a.hashCode() * 31, 31, this.b) + this.c)) * 31)) * 31) + this.e;
        long jFloatToRawIntBits = Float.floatToRawIntBits(this.f);
        return (((iK * 31) + ((int) (jFloatToRawIntBits ^ (jFloatToRawIntBits >>> 32)))) * 31) + this.h;
    }
}
