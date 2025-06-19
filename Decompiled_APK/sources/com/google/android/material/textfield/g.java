package com.google.android.material.textfield;

import android.graphics.Canvas;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;

/* loaded from: classes2.dex */
public final class g extends com.google.android.material.shape.g {
    public static final /* synthetic */ int z = 0;
    public f y;

    @Override // com.google.android.material.shape.g
    public final void f(Canvas canvas) {
        if (this.y.s.isEmpty()) {
            super.f(canvas);
            return;
        }
        canvas.save();
        canvas.clipOutRect(this.y.s);
        super.f(canvas);
        canvas.restore();
    }

    @Override // com.google.android.material.shape.g, android.graphics.drawable.Drawable
    public final Drawable mutate() {
        this.y = new f(this.y);
        return this;
    }

    public final void v(float f, float f2, float f3, float f4) {
        RectF rectF = this.y.s;
        if (f == rectF.left && f2 == rectF.top && f3 == rectF.right && f4 == rectF.bottom) {
            return;
        }
        rectF.set(f, f2, f3, f4);
        invalidateSelf();
    }
}
