package it.sephiroth.android.library.xtooltip;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.view.animation.AccelerateDecelerateInterpolator;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l extends Drawable {
    public final Paint a;
    public final Paint b;
    public float c;
    public final AnimatorSet d;
    public final AnimatorSet e;
    public final ObjectAnimator f;
    public final ObjectAnimator g;
    public int h;
    public boolean i;
    public final int j;
    public final long k;

    public l(Context context, int i) throws Resources.NotFoundException {
        Paint paint = new Paint(1);
        this.a = paint;
        Paint paint2 = new Paint(1);
        this.b = paint2;
        this.j = 1;
        this.k = 400L;
        Paint.Style style = Paint.Style.FILL;
        paint.setStyle(style);
        paint2.setStyle(style);
        TypedArray array = context.getTheme().obtainStyledAttributes(i, b.b);
        Intrinsics.c(array, "array");
        int indexCount = array.getIndexCount();
        for (int i2 = 0; i2 < indexCount; i2++) {
            int index = array.getIndex(i2);
            if (index == 1) {
                int color = array.getColor(index, 0);
                this.a.setColor(color);
                this.b.setColor(color);
            } else if (index == 4) {
                this.j = array.getInt(index, 1);
            } else if (index == 2) {
                int i3 = (int) (array.getFloat(index, this.b.getAlpha() / 255.0f) * 255);
                this.b.setAlpha(i3);
                this.a.setAlpha(i3);
            } else if (index == 3) {
                this.k = array.getInt(index, 400);
            }
        }
        array.recycle();
        int alpha = this.a.getAlpha();
        int alpha2 = this.b.getAlpha();
        ObjectAnimator objectAnimatorOfInt = ObjectAnimator.ofInt(this, "outerAlpha", 0, alpha);
        Intrinsics.c(objectAnimatorOfInt, "ObjectAnimator.ofInt(thi…erAlpha\", 0, mOuterAlpha)");
        objectAnimatorOfInt.setDuration((long) (this.k * 0.3d));
        ObjectAnimator objectAnimatorOfInt2 = ObjectAnimator.ofInt(this, "outerAlpha", alpha, 0, 0);
        Intrinsics.c(objectAnimatorOfInt2, "ObjectAnimator.ofInt(thi…lpha\", mOuterAlpha, 0, 0)");
        objectAnimatorOfInt2.setStartDelay((long) (this.k * 0.55d));
        objectAnimatorOfInt2.setDuration((long) (this.k * 0.44999999999999996d));
        ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(this, "outerRadius", DefinitionKt.NO_Float_VALUE, 1.0f);
        Intrinsics.c(objectAnimatorOfFloat, "ObjectAnimator.ofFloat(t…s, \"outerRadius\", 0f, 1f)");
        this.f = objectAnimatorOfFloat;
        objectAnimatorOfFloat.setDuration(this.k);
        AnimatorSet animatorSet = new AnimatorSet();
        this.d = animatorSet;
        animatorSet.playTogether(objectAnimatorOfInt, objectAnimatorOfFloat, objectAnimatorOfInt2);
        animatorSet.setInterpolator(new AccelerateDecelerateInterpolator());
        animatorSet.setDuration(this.k);
        ObjectAnimator objectAnimatorOfInt3 = ObjectAnimator.ofInt(this, "innerAlpha", 0, alpha2);
        Intrinsics.c(objectAnimatorOfInt3, "ObjectAnimator.ofInt(thi…erAlpha\", 0, mInnerAlpha)");
        objectAnimatorOfInt3.setDuration((long) (this.k * 0.3d));
        ObjectAnimator objectAnimatorOfInt4 = ObjectAnimator.ofInt(this, "innerAlpha", alpha2, 0, 0);
        Intrinsics.c(objectAnimatorOfInt4, "ObjectAnimator.ofInt(thi…lpha\", mInnerAlpha, 0, 0)");
        objectAnimatorOfInt4.setStartDelay((long) (this.k * 0.55d));
        objectAnimatorOfInt4.setDuration((long) (this.k * 0.44999999999999996d));
        ObjectAnimator objectAnimatorOfFloat2 = ObjectAnimator.ofFloat(this, "innerRadius", DefinitionKt.NO_Float_VALUE, 1.0f);
        Intrinsics.c(objectAnimatorOfFloat2, "ObjectAnimator.ofFloat(t…s, \"innerRadius\", 0f, 1f)");
        this.g = objectAnimatorOfFloat2;
        objectAnimatorOfFloat2.setDuration(this.k);
        AnimatorSet animatorSet2 = new AnimatorSet();
        this.e = animatorSet2;
        animatorSet2.playTogether(objectAnimatorOfInt3, objectAnimatorOfFloat2, objectAnimatorOfInt4);
        animatorSet2.setInterpolator(new AccelerateDecelerateInterpolator());
        animatorSet2.setStartDelay((long) (this.k * 0.25d));
        animatorSet2.setDuration(this.k);
        animatorSet.addListener(new k(this, 0));
        animatorSet2.addListener(new k(this, 1));
    }

    @Override // android.graphics.drawable.Drawable
    public final void draw(Canvas canvas) {
        Intrinsics.f(canvas, "canvas");
        Rect bounds = getBounds();
        float fWidth = bounds.width() / 2;
        float fHeight = bounds.height() / 2;
        canvas.drawCircle(fWidth, fHeight, this.c, this.a);
        canvas.drawCircle(fWidth, fHeight, DefinitionKt.NO_Float_VALUE, this.b);
    }

    @Override // android.graphics.drawable.Drawable
    public final int getIntrinsicHeight() {
        return 96;
    }

    @Override // android.graphics.drawable.Drawable
    public final int getIntrinsicWidth() {
        return 96;
    }

    @Override // android.graphics.drawable.Drawable
    public final int getOpacity() {
        return -3;
    }

    @Override // android.graphics.drawable.Drawable
    public final void onBoundsChange(Rect bounds) {
        Intrinsics.f(bounds, "bounds");
        timber.log.c.a.g("onBoundsChange: " + bounds, new Object[0]);
        super.onBoundsChange(bounds);
        float fMin = (float) (Math.min(bounds.width(), bounds.height()) / 2);
        this.c = fMin;
        this.f.setFloatValues(DefinitionKt.NO_Float_VALUE, fMin);
        this.g.setFloatValues(DefinitionKt.NO_Float_VALUE, this.c);
    }

    @Override // android.graphics.drawable.Drawable
    public final void setAlpha(int i) {
    }

    @Override // android.graphics.drawable.Drawable
    public final void setColorFilter(ColorFilter colorFilter) {
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean setVisible(boolean z, boolean z2) {
        boolean z3 = isVisible() != z;
        AnimatorSet animatorSet = this.e;
        AnimatorSet animatorSet2 = this.d;
        if (!z) {
            animatorSet2.cancel();
            animatorSet.cancel();
            this.h = 0;
            this.i = false;
            invalidateSelf();
            this.c = DefinitionKt.NO_Float_VALUE;
            invalidateSelf();
            return z3;
        }
        if (!z2 && this.i) {
            return z3;
        }
        animatorSet2.cancel();
        animatorSet.cancel();
        this.h = 0;
        this.i = false;
        invalidateSelf();
        this.c = DefinitionKt.NO_Float_VALUE;
        invalidateSelf();
        this.h = 0;
        this.i = true;
        animatorSet2.start();
        animatorSet.setStartDelay((long) (this.k * 0.25d));
        animatorSet.start();
        return z3;
    }
}
