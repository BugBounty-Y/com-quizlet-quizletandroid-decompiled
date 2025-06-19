package com.quizlet.uicommon.ui.common.views;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;
import com.quizlet.quizletandroid.R;
import com.quizlet.themes.extensions.a;

/* loaded from: classes3.dex */
public class ArcProgressBar extends View {
    public final Paint a;
    public final Paint b;
    public final RectF c;
    public final float d;
    public int e;
    public int f;

    public ArcProgressBar(Context context) {
        this(context, null, 0);
    }

    public int getBackgroundColor() {
        return this.b.getColor();
    }

    public int getColor() {
        return this.a.getColor();
    }

    public int getMaxValue() {
        return this.f;
    }

    public int getProgress() {
        return this.e;
    }

    @Override // android.view.View
    public final void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int iMin = Math.min(getWidth(), getHeight());
        float f = this.d;
        float f2 = iMin - f;
        float f3 = (f / 2.0f) + ((r0 - iMin) / 2);
        float f4 = (f / 2.0f) + ((r1 - iMin) / 2);
        RectF rectF = this.c;
        rectF.set(f3, f4, f3 + f2, f2 + f4);
        canvas.drawArc(rectF, 135.0f, 270.0f, false, this.b);
        if (this.e > 0) {
            canvas.drawArc(rectF, 135.0f, Math.round(((r14 * 1.0f) / this.f) * 270.0f), false, this.a);
        }
    }

    @Override // android.view.View
    public void setBackgroundColor(int i) {
        this.b.setColor(i);
    }

    public void setColor(int i) {
        this.a.setColor(i);
    }

    public void setMaxValue(int i) {
        boolean z = this.f != i;
        this.f = i;
        if (z) {
            invalidate();
        }
    }

    public void setProgress(int i) {
        boolean z = this.e != i;
        this.e = i;
        if (z) {
            invalidate();
        }
    }

    public ArcProgressBar(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public ArcProgressBar(Context context, AttributeSet attributeSet, int i) throws Resources.NotFoundException {
        super(context, attributeSet, 0);
        int iA = a.a(context, R.attr.colorProgressBar);
        int iA2 = a.a(context, R.attr.iconColorPrimaryInverse);
        this.e = 0;
        this.f = 100;
        float dimension = getResources().getDimension(R.dimen.percentarcview_default_stroke_width);
        this.d = dimension;
        if (attributeSet != null) {
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.quizlet.quizletandroid.ui.common.a.a);
            iA = typedArrayObtainStyledAttributes.getColor(2, iA);
            this.e = typedArrayObtainStyledAttributes.getInt(1, this.e);
            this.f = typedArrayObtainStyledAttributes.getInt(0, this.f);
            iA2 = typedArrayObtainStyledAttributes.getColor(3, iA2);
            this.d = typedArrayObtainStyledAttributes.getDimension(4, dimension);
            typedArrayObtainStyledAttributes.recycle();
        }
        Paint paint = new Paint();
        this.a = paint;
        paint.setAntiAlias(true);
        paint.setColor(iA);
        paint.setStrokeWidth(this.d);
        Paint.Style style = Paint.Style.STROKE;
        paint.setStyle(style);
        Paint.Cap cap = Paint.Cap.ROUND;
        paint.setStrokeCap(cap);
        Paint paint2 = new Paint();
        this.b = paint2;
        paint2.setAntiAlias(true);
        paint2.setColor(iA2);
        paint2.setStrokeWidth(this.d);
        paint2.setStyle(style);
        paint2.setStrokeCap(cap);
        this.c = new RectF();
    }
}
