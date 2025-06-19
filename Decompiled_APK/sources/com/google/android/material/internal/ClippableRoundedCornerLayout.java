package com.google.android.material.internal;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class ClippableRoundedCornerLayout extends FrameLayout {
    public Path a;
    public float b;

    public ClippableRoundedCornerLayout(@NonNull Context context) {
        super(context);
    }

    public final void a(float f, float f2, float f3, float f4, float f5) {
        RectF rectF = new RectF(f, f2, f3, f4);
        if (this.a == null) {
            this.a = new Path();
        }
        this.b = f5;
        this.a.reset();
        this.a.addRoundRect(rectF, f5, f5, Path.Direction.CW);
        this.a.close();
        invalidate();
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void dispatchDraw(Canvas canvas) {
        if (this.a == null) {
            super.dispatchDraw(canvas);
            return;
        }
        int iSave = canvas.save();
        canvas.clipPath(this.a);
        super.dispatchDraw(canvas);
        canvas.restoreToCount(iSave);
    }

    public float getCornerRadius() {
        return this.b;
    }

    public ClippableRoundedCornerLayout(@NonNull Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
    }
}
