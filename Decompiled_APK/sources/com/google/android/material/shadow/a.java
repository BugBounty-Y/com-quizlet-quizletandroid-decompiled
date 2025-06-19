package com.google.android.material.shadow;

import android.graphics.Paint;
import android.graphics.Path;
import androidx.core.graphics.d;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class a {
    public static final int[] i = new int[3];
    public static final float[] j = {DefinitionKt.NO_Float_VALUE, 0.5f, 1.0f};
    public static final int[] k = new int[4];
    public static final float[] l = {DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0.5f, 1.0f};
    public final Paint a;
    public final Paint b;
    public final Paint c;
    public int d;
    public int e;
    public int f;
    public final Path g = new Path();
    public final Paint h;

    public a() {
        Paint paint = new Paint();
        this.h = paint;
        this.a = new Paint();
        a(-16777216);
        paint.setColor(0);
        Paint paint2 = new Paint(4);
        this.b = paint2;
        paint2.setStyle(Paint.Style.FILL);
        this.c = new Paint(paint2);
    }

    public final void a(int i2) {
        this.d = d.d(i2, 68);
        this.e = d.d(i2, 20);
        this.f = d.d(i2, 0);
        this.a.setColor(this.d);
    }
}
