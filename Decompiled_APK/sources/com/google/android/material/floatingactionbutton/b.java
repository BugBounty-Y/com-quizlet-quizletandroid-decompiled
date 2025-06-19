package com.google.android.material.floatingactionbutton;

import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.LinearGradient;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;
import com.google.android.gms.internal.ads.C2538qn;
import com.google.android.gms.internal.mlkit_vision_common.Y3;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class b extends Drawable {
    public final Paint b;
    public float h;
    public int i;
    public int j;
    public int k;
    public int l;
    public int m;
    public com.google.android.material.shape.j o;
    public ColorStateList p;
    public final C2538qn a = com.google.android.material.shape.k.a;
    public final Path c = new Path();
    public final Rect d = new Rect();
    public final RectF e = new RectF();
    public final RectF f = new RectF();
    public final androidx.vectordrawable.graphics.drawable.e g = new androidx.vectordrawable.graphics.drawable.e(this);
    public boolean n = true;

    public b(com.google.android.material.shape.j jVar) {
        this.o = jVar;
        Paint paint = new Paint(1);
        this.b = paint;
        paint.setStyle(Paint.Style.STROKE);
    }

    @Override // android.graphics.drawable.Drawable
    public final void draw(Canvas canvas) {
        boolean z = this.n;
        Paint paint = this.b;
        Rect rect = this.d;
        if (z) {
            copyBounds(rect);
            float fHeight = this.h / rect.height();
            paint.setShader(new LinearGradient(DefinitionKt.NO_Float_VALUE, rect.top, DefinitionKt.NO_Float_VALUE, rect.bottom, new int[]{androidx.core.graphics.d.b(this.i, this.m), androidx.core.graphics.d.b(this.j, this.m), androidx.core.graphics.d.b(androidx.core.graphics.d.d(this.j, 0), this.m), androidx.core.graphics.d.b(androidx.core.graphics.d.d(this.l, 0), this.m), androidx.core.graphics.d.b(this.l, this.m), androidx.core.graphics.d.b(this.k, this.m)}, new float[]{DefinitionKt.NO_Float_VALUE, fHeight, 0.5f, 0.5f, 1.0f - fHeight, 1.0f}, Shader.TileMode.CLAMP));
            this.n = false;
        }
        float strokeWidth = paint.getStrokeWidth() / 2.0f;
        copyBounds(rect);
        RectF rectF = this.e;
        rectF.set(rect);
        com.google.android.material.shape.c cVar = this.o.e;
        RectF rectF2 = this.f;
        rectF2.set(getBounds());
        float fMin = Math.min(cVar.a(rectF2), rectF.width() / 2.0f);
        com.google.android.material.shape.j jVar = this.o;
        rectF2.set(getBounds());
        if (jVar.e(rectF2)) {
            rectF.inset(strokeWidth, strokeWidth);
            canvas.drawRoundRect(rectF, fMin, fMin, paint);
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final Drawable.ConstantState getConstantState() {
        return this.g;
    }

    @Override // android.graphics.drawable.Drawable
    public final int getOpacity() {
        return this.h > DefinitionKt.NO_Float_VALUE ? -3 : -2;
    }

    @Override // android.graphics.drawable.Drawable
    public final void getOutline(Outline outline) {
        com.google.android.material.shape.j jVar = this.o;
        RectF rectF = this.f;
        rectF.set(getBounds());
        if (jVar.e(rectF)) {
            com.google.android.material.shape.c cVar = this.o.e;
            rectF.set(getBounds());
            outline.setRoundRect(getBounds(), cVar.a(rectF));
            return;
        }
        Rect rect = this.d;
        copyBounds(rect);
        RectF rectF2 = this.e;
        rectF2.set(rect);
        com.google.android.material.shape.j jVar2 = this.o;
        Path path = this.c;
        this.a.a(jVar2, 1.0f, rectF2, null, path);
        Y3.k(outline, path);
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean getPadding(Rect rect) {
        com.google.android.material.shape.j jVar = this.o;
        RectF rectF = this.f;
        rectF.set(getBounds());
        if (!jVar.e(rectF)) {
            return true;
        }
        int iRound = Math.round(this.h);
        rect.set(iRound, iRound, iRound, iRound);
        return true;
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean isStateful() {
        ColorStateList colorStateList = this.p;
        return (colorStateList != null && colorStateList.isStateful()) || super.isStateful();
    }

    @Override // android.graphics.drawable.Drawable
    public final void onBoundsChange(Rect rect) {
        this.n = true;
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean onStateChange(int[] iArr) {
        int colorForState;
        ColorStateList colorStateList = this.p;
        if (colorStateList != null && (colorForState = colorStateList.getColorForState(iArr, this.m)) != this.m) {
            this.n = true;
            this.m = colorForState;
        }
        if (this.n) {
            invalidateSelf();
        }
        return this.n;
    }

    @Override // android.graphics.drawable.Drawable
    public final void setAlpha(int i) {
        this.b.setAlpha(i);
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public final void setColorFilter(ColorFilter colorFilter) {
        this.b.setColorFilter(colorFilter);
        invalidateSelf();
    }
}
