package com.google.android.material.shape;

import android.content.res.ColorStateList;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public class f extends Drawable.ConstantState {
    public j a;
    public com.google.android.material.elevation.a b;
    public ColorStateList c;
    public ColorStateList d;
    public ColorStateList e;
    public PorterDuff.Mode f;
    public Rect g;
    public final float h;
    public float i;
    public float j;
    public int k;
    public float l;
    public float m;
    public int n;
    public int o;
    public int p;
    public final int q;
    public Paint.Style r;

    public f(j jVar) {
        this.c = null;
        this.d = null;
        this.e = null;
        this.f = PorterDuff.Mode.SRC_IN;
        this.g = null;
        this.h = 1.0f;
        this.i = 1.0f;
        this.k = 255;
        this.l = DefinitionKt.NO_Float_VALUE;
        this.m = DefinitionKt.NO_Float_VALUE;
        this.n = 0;
        this.o = 0;
        this.p = 0;
        this.q = 0;
        this.r = Paint.Style.FILL_AND_STROKE;
        this.a = jVar;
        this.b = null;
    }

    @Override // android.graphics.drawable.Drawable.ConstantState
    public final int getChangingConfigurations() {
        return 0;
    }

    @Override // android.graphics.drawable.Drawable.ConstantState
    public Drawable newDrawable() {
        g gVar = new g(this);
        gVar.e = true;
        return gVar;
    }

    public f(f fVar) {
        this.c = null;
        this.d = null;
        this.e = null;
        this.f = PorterDuff.Mode.SRC_IN;
        this.g = null;
        this.h = 1.0f;
        this.i = 1.0f;
        this.k = 255;
        this.l = DefinitionKt.NO_Float_VALUE;
        this.m = DefinitionKt.NO_Float_VALUE;
        this.n = 0;
        this.o = 0;
        this.p = 0;
        this.q = 0;
        this.r = Paint.Style.FILL_AND_STROKE;
        this.a = fVar.a;
        this.b = fVar.b;
        this.j = fVar.j;
        this.c = fVar.c;
        this.d = fVar.d;
        this.f = fVar.f;
        this.e = fVar.e;
        this.k = fVar.k;
        this.h = fVar.h;
        this.p = fVar.p;
        this.n = fVar.n;
        this.i = fVar.i;
        this.l = fVar.l;
        this.m = fVar.m;
        this.o = fVar.o;
        this.q = fVar.q;
        this.r = fVar.r;
        if (fVar.g != null) {
            this.g = new Rect(fVar.g);
        }
    }
}
