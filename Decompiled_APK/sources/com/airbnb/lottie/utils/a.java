package com.airbnb.lottie.utils;

import android.graphics.Color;
import android.graphics.Matrix;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class a {
    public float a;
    public float b;
    public float c;
    public int d;
    public float[] e = null;

    public a(a aVar) {
        this.a = DefinitionKt.NO_Float_VALUE;
        this.b = DefinitionKt.NO_Float_VALUE;
        this.c = DefinitionKt.NO_Float_VALUE;
        this.d = 0;
        this.a = aVar.a;
        this.b = aVar.b;
        this.c = aVar.c;
        this.d = aVar.d;
    }

    public final void a(int i, com.airbnb.lottie.animation.a aVar) {
        int iAlpha = Color.alpha(this.d);
        int iC = g.c(i);
        Matrix matrix = i.a;
        int i2 = (int) ((((iAlpha / 255.0f) * iC) / 255.0f) * 255.0f);
        if (i2 <= 0) {
            aVar.clearShadowLayer();
        } else {
            aVar.setShadowLayer(Math.max(this.a, Float.MIN_VALUE), this.b, this.c, Color.argb(i2, Color.red(this.d), Color.green(this.d), Color.blue(this.d)));
        }
    }

    public final void b(int i) {
        this.d = Color.argb(Math.round((g.c(i) * Color.alpha(this.d)) / 255.0f), Color.red(this.d), Color.green(this.d), Color.blue(this.d));
    }

    public final void c(Matrix matrix) {
        if (this.e == null) {
            this.e = new float[2];
        }
        float[] fArr = this.e;
        fArr[0] = this.b;
        fArr[1] = this.c;
        matrix.mapVectors(fArr);
        float[] fArr2 = this.e;
        this.b = fArr2[0];
        this.c = fArr2[1];
        this.a = matrix.mapRadius(this.a);
    }
}
