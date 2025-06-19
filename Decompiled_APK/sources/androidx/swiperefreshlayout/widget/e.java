package androidx.swiperefreshlayout.widget;

import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import android.view.animation.LinearInterpolator;
import androidx.annotation.NonNull;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public class e extends Drawable implements Animatable {
    public static final LinearInterpolator g = new LinearInterpolator();
    public static final androidx.interpolator.view.animation.a h = new androidx.interpolator.view.animation.a(1);
    public static final int[] i = {-16777216};
    public final d a;
    public float b;
    public final Resources c;
    public final ValueAnimator d;
    public float e;
    public boolean f;

    public e(@NonNull Context context) {
        context.getClass();
        this.c = context.getResources();
        d dVar = new d();
        this.a = dVar;
        dVar.i = i;
        dVar.a(0);
        dVar.h = 2.5f;
        dVar.b.setStrokeWidth(2.5f);
        invalidateSelf();
        ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(DefinitionKt.NO_Float_VALUE, 1.0f);
        valueAnimatorOfFloat.addUpdateListener(new b(this, dVar));
        valueAnimatorOfFloat.setRepeatCount(-1);
        valueAnimatorOfFloat.setRepeatMode(1);
        valueAnimatorOfFloat.setInterpolator(g);
        valueAnimatorOfFloat.addListener(new c(this, dVar));
        this.d = valueAnimatorOfFloat;
    }

    public static void d(float f, d dVar) {
        if (f <= 0.75f) {
            dVar.u = dVar.i[dVar.j];
            return;
        }
        float f2 = (f - 0.75f) / 0.25f;
        int[] iArr = dVar.i;
        int i2 = dVar.j;
        int i3 = iArr[i2];
        int i4 = iArr[(i2 + 1) % iArr.length];
        dVar.u = ((((i3 >> 24) & 255) + ((int) ((((i4 >> 24) & 255) - r1) * f2))) << 24) | ((((i3 >> 16) & 255) + ((int) ((((i4 >> 16) & 255) - r3) * f2))) << 16) | ((((i3 >> 8) & 255) + ((int) ((((i4 >> 8) & 255) - r4) * f2))) << 8) | ((i3 & 255) + ((int) (f2 * ((i4 & 255) - r2))));
    }

    public final void a(float f, d dVar, boolean z) {
        float interpolation;
        float interpolation2;
        if (this.f) {
            d(f, dVar);
            float fFloor = (float) (Math.floor(dVar.m / 0.8f) + 1.0d);
            float f2 = dVar.k;
            float f3 = dVar.l;
            dVar.e = (((f3 - 0.01f) - f2) * f) + f2;
            dVar.f = f3;
            float f4 = dVar.m;
            dVar.g = android.support.v4.media.session.a.a(fFloor, f4, f, f4);
            return;
        }
        if (f != 1.0f || z) {
            float f5 = dVar.m;
            androidx.interpolator.view.animation.a aVar = h;
            if (f < 0.5f) {
                interpolation = dVar.k;
                interpolation2 = (aVar.getInterpolation(f / 0.5f) * 0.79f) + 0.01f + interpolation;
            } else {
                float f6 = dVar.k + 0.79f;
                interpolation = f6 - (((1.0f - aVar.getInterpolation((f - 0.5f) / 0.5f)) * 0.79f) + 0.01f);
                interpolation2 = f6;
            }
            float f7 = (0.20999998f * f) + f5;
            float f8 = (f + this.e) * 216.0f;
            dVar.e = interpolation;
            dVar.f = interpolation2;
            dVar.g = f7;
            this.b = f8;
        }
    }

    public final void b(float f, float f2, float f3, float f4) {
        float f5 = this.c.getDisplayMetrics().density;
        float f6 = f2 * f5;
        d dVar = this.a;
        dVar.h = f6;
        dVar.b.setStrokeWidth(f6);
        dVar.q = f * f5;
        dVar.a(0);
        dVar.r = (int) (f3 * f5);
        dVar.s = (int) (f4 * f5);
    }

    public final void c(int i2) {
        if (i2 == 0) {
            b(11.0f, 3.0f, 12.0f, 6.0f);
        } else {
            b(7.5f, 2.5f, 10.0f, 5.0f);
        }
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public final void draw(Canvas canvas) {
        Rect bounds = getBounds();
        canvas.save();
        canvas.rotate(this.b, bounds.exactCenterX(), bounds.exactCenterY());
        d dVar = this.a;
        RectF rectF = dVar.a;
        float f = dVar.q;
        float fMin = (dVar.h / 2.0f) + f;
        if (f <= DefinitionKt.NO_Float_VALUE) {
            fMin = (Math.min(bounds.width(), bounds.height()) / 2.0f) - Math.max((dVar.r * dVar.p) / 2.0f, dVar.h / 2.0f);
        }
        rectF.set(bounds.centerX() - fMin, bounds.centerY() - fMin, bounds.centerX() + fMin, bounds.centerY() + fMin);
        float f2 = dVar.e;
        float f3 = dVar.g;
        float f4 = (f2 + f3) * 360.0f;
        float f5 = ((dVar.f + f3) * 360.0f) - f4;
        Paint paint = dVar.b;
        paint.setColor(dVar.u);
        paint.setAlpha(dVar.t);
        float f6 = dVar.h / 2.0f;
        rectF.inset(f6, f6);
        canvas.drawCircle(rectF.centerX(), rectF.centerY(), rectF.width() / 2.0f, dVar.d);
        float f7 = -f6;
        rectF.inset(f7, f7);
        canvas.drawArc(rectF, f4, f5, false, paint);
        if (dVar.n) {
            Path path = dVar.o;
            if (path == null) {
                Path path2 = new Path();
                dVar.o = path2;
                path2.setFillType(Path.FillType.EVEN_ODD);
            } else {
                path.reset();
            }
            float fMin2 = Math.min(rectF.width(), rectF.height()) / 2.0f;
            float f8 = (dVar.r * dVar.p) / 2.0f;
            dVar.o.moveTo(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
            dVar.o.lineTo(dVar.r * dVar.p, DefinitionKt.NO_Float_VALUE);
            Path path3 = dVar.o;
            float f9 = dVar.r;
            float f10 = dVar.p;
            path3.lineTo((f9 * f10) / 2.0f, dVar.s * f10);
            dVar.o.offset((rectF.centerX() + fMin2) - f8, (dVar.h / 2.0f) + rectF.centerY());
            dVar.o.close();
            Paint paint2 = dVar.c;
            paint2.setColor(dVar.u);
            paint2.setAlpha(dVar.t);
            canvas.save();
            canvas.rotate(f4 + f5, rectF.centerX(), rectF.centerY());
            canvas.drawPath(dVar.o, paint2);
            canvas.restore();
        }
        canvas.restore();
    }

    @Override // android.graphics.drawable.Drawable
    public final int getAlpha() {
        return this.a.t;
    }

    @Override // android.graphics.drawable.Drawable
    public final int getOpacity() {
        return -3;
    }

    @Override // android.graphics.drawable.Animatable
    public final boolean isRunning() {
        return this.d.isRunning();
    }

    @Override // android.graphics.drawable.Drawable
    public final void setAlpha(int i2) {
        this.a.t = i2;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public final void setColorFilter(ColorFilter colorFilter) {
        this.a.b.setColorFilter(colorFilter);
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Animatable
    public final void start() {
        this.d.cancel();
        d dVar = this.a;
        float f = dVar.e;
        dVar.k = f;
        float f2 = dVar.f;
        dVar.l = f2;
        dVar.m = dVar.g;
        if (f2 != f) {
            this.f = true;
            this.d.setDuration(666L);
            this.d.start();
            return;
        }
        dVar.a(0);
        dVar.k = DefinitionKt.NO_Float_VALUE;
        dVar.l = DefinitionKt.NO_Float_VALUE;
        dVar.m = DefinitionKt.NO_Float_VALUE;
        dVar.e = DefinitionKt.NO_Float_VALUE;
        dVar.f = DefinitionKt.NO_Float_VALUE;
        dVar.g = DefinitionKt.NO_Float_VALUE;
        this.d.setDuration(1332L);
        this.d.start();
    }

    @Override // android.graphics.drawable.Animatable
    public final void stop() {
        this.d.cancel();
        this.b = DefinitionKt.NO_Float_VALUE;
        d dVar = this.a;
        if (dVar.n) {
            dVar.n = false;
        }
        dVar.a(0);
        dVar.k = DefinitionKt.NO_Float_VALUE;
        dVar.l = DefinitionKt.NO_Float_VALUE;
        dVar.m = DefinitionKt.NO_Float_VALUE;
        dVar.e = DefinitionKt.NO_Float_VALUE;
        dVar.f = DefinitionKt.NO_Float_VALUE;
        dVar.g = DefinitionKt.NO_Float_VALUE;
        invalidateSelf();
    }
}
