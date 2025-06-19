package com.airbnb.lottie.value;

import android.graphics.PointF;
import android.view.animation.BaseInterpolator;
import com.airbnb.lottie.h;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public class a {
    public final h a;
    public final Object b;
    public Object c;
    public final BaseInterpolator d;
    public final BaseInterpolator e;
    public final BaseInterpolator f;
    public final float g;
    public Float h;
    public float i;
    public float j;
    public int k;
    public int l;
    public float m;
    public float n;
    public PointF o;
    public PointF p;

    public a(h hVar, Object obj, Object obj2, BaseInterpolator baseInterpolator, float f, Float f2) {
        this.i = -3987645.8f;
        this.j = -3987645.8f;
        this.k = 784923401;
        this.l = 784923401;
        this.m = Float.MIN_VALUE;
        this.n = Float.MIN_VALUE;
        this.o = null;
        this.p = null;
        this.a = hVar;
        this.b = obj;
        this.c = obj2;
        this.d = baseInterpolator;
        this.e = null;
        this.f = null;
        this.g = f;
        this.h = f2;
    }

    public final float a() {
        if (this.a == null) {
            return 1.0f;
        }
        if (this.n == Float.MIN_VALUE) {
            if (this.h == null) {
                this.n = 1.0f;
            } else {
                this.n = (float) (b() + ((this.h.floatValue() - this.g) / (r1.m - r1.l)));
            }
        }
        return this.n;
    }

    public final float b() {
        h hVar = this.a;
        if (hVar == null) {
            return DefinitionKt.NO_Float_VALUE;
        }
        if (this.m == Float.MIN_VALUE) {
            float f = hVar.l;
            this.m = (this.g - f) / (hVar.m - f);
        }
        return this.m;
    }

    public final boolean c() {
        return this.d == null && this.e == null && this.f == null;
    }

    public final String toString() {
        return "Keyframe{startValue=" + this.b + ", endValue=" + this.c + ", startFrame=" + this.g + ", endFrame=" + this.h + ", interpolator=" + this.d + '}';
    }

    public a(h hVar, Object obj, Object obj2, BaseInterpolator baseInterpolator, BaseInterpolator baseInterpolator2, float f) {
        this.i = -3987645.8f;
        this.j = -3987645.8f;
        this.k = 784923401;
        this.l = 784923401;
        this.m = Float.MIN_VALUE;
        this.n = Float.MIN_VALUE;
        this.o = null;
        this.p = null;
        this.a = hVar;
        this.b = obj;
        this.c = obj2;
        this.d = null;
        this.e = baseInterpolator;
        this.f = baseInterpolator2;
        this.g = f;
        this.h = null;
    }

    public a(h hVar, Object obj, Object obj2, BaseInterpolator baseInterpolator, BaseInterpolator baseInterpolator2, BaseInterpolator baseInterpolator3, float f, Float f2) {
        this.i = -3987645.8f;
        this.j = -3987645.8f;
        this.k = 784923401;
        this.l = 784923401;
        this.m = Float.MIN_VALUE;
        this.n = Float.MIN_VALUE;
        this.o = null;
        this.p = null;
        this.a = hVar;
        this.b = obj;
        this.c = obj2;
        this.d = baseInterpolator;
        this.e = baseInterpolator2;
        this.f = baseInterpolator3;
        this.g = f;
        this.h = f2;
    }

    public a(Object obj) {
        this.i = -3987645.8f;
        this.j = -3987645.8f;
        this.k = 784923401;
        this.l = 784923401;
        this.m = Float.MIN_VALUE;
        this.n = Float.MIN_VALUE;
        this.o = null;
        this.p = null;
        this.a = null;
        this.b = obj;
        this.c = obj;
        this.d = null;
        this.e = null;
        this.f = null;
        this.g = Float.MIN_VALUE;
        this.h = Float.valueOf(Float.MAX_VALUE);
    }

    public a(com.airbnb.lottie.model.content.c cVar, com.airbnb.lottie.model.content.c cVar2) {
        this.i = -3987645.8f;
        this.j = -3987645.8f;
        this.k = 784923401;
        this.l = 784923401;
        this.m = Float.MIN_VALUE;
        this.n = Float.MIN_VALUE;
        this.o = null;
        this.p = null;
        this.a = null;
        this.b = cVar;
        this.c = cVar2;
        this.d = null;
        this.e = null;
        this.f = null;
        this.g = Float.MIN_VALUE;
        this.h = Float.valueOf(Float.MAX_VALUE);
    }
}
