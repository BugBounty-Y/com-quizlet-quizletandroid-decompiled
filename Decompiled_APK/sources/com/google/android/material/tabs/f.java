package com.google.android.material.tabs;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.widget.LinearLayout;
import androidx.core.view.V;
import com.google.android.material.internal.p;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class f extends LinearLayout {
    public static final /* synthetic */ int c = 0;
    public ValueAnimator a;
    public final /* synthetic */ l b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(l lVar, Context context) {
        super(context);
        this.b = lVar;
        setWillNotDraw(false);
    }

    public final void a(int i) {
        l lVar = this.b;
        if (lVar.h1 == 0 || (lVar.getTabSelectedIndicator().getBounds().left == -1 && lVar.getTabSelectedIndicator().getBounds().right == -1)) {
            View childAt = getChildAt(i);
            com.google.android.material.shape.e eVar = lVar.I;
            Drawable drawable = lVar.o;
            eVar.getClass();
            RectF rectFS = com.google.android.material.shape.e.s(lVar, childAt);
            drawable.setBounds((int) rectFS.left, drawable.getBounds().top, (int) rectFS.right, drawable.getBounds().bottom);
            lVar.a = i;
        }
    }

    public final void b(int i) {
        l lVar = this.b;
        Rect bounds = lVar.o.getBounds();
        lVar.o.setBounds(bounds.left, 0, bounds.right, i);
        requestLayout();
    }

    public final void c(View view, View view2, float f) {
        l lVar = this.b;
        if (view == null || view.getWidth() <= 0) {
            Drawable drawable = lVar.o;
            drawable.setBounds(-1, drawable.getBounds().top, -1, lVar.o.getBounds().bottom);
        } else {
            lVar.I.w(lVar, view, view2, f, lVar.o);
        }
        WeakHashMap weakHashMap = V.a;
        postInvalidateOnAnimation();
    }

    public final void d(int i, int i2, boolean z) {
        l lVar = this.b;
        if (lVar.a == i) {
            return;
        }
        View childAt = getChildAt(lVar.getSelectedTabPosition());
        View childAt2 = getChildAt(i);
        if (childAt2 == null) {
            a(lVar.getSelectedTabPosition());
            return;
        }
        lVar.a = i;
        com.google.android.material.internal.e eVar = new com.google.android.material.internal.e(this, childAt, childAt2);
        if (!z) {
            this.a.removeAllUpdateListeners();
            this.a.addUpdateListener(eVar);
            return;
        }
        ValueAnimator valueAnimator = new ValueAnimator();
        this.a = valueAnimator;
        valueAnimator.setInterpolator(lVar.J);
        valueAnimator.setDuration(i2);
        valueAnimator.setFloatValues(DefinitionKt.NO_Float_VALUE, 1.0f);
        valueAnimator.addUpdateListener(eVar);
        valueAnimator.start();
    }

    @Override // android.view.View
    public final void draw(Canvas canvas) {
        int height;
        l lVar = this.b;
        int iHeight = lVar.o.getBounds().height();
        if (iHeight < 0) {
            iHeight = lVar.o.getIntrinsicHeight();
        }
        int i = lVar.B;
        if (i == 0) {
            height = getHeight() - iHeight;
            iHeight = getHeight();
        } else if (i != 1) {
            height = 0;
            if (i != 2) {
                iHeight = i != 3 ? 0 : getHeight();
            }
        } else {
            height = (getHeight() - iHeight) / 2;
            iHeight = (getHeight() + iHeight) / 2;
        }
        if (lVar.o.getBounds().width() > 0) {
            Rect bounds = lVar.o.getBounds();
            lVar.o.setBounds(bounds.left, height, bounds.right, iHeight);
            lVar.o.draw(canvas);
        }
        super.draw(canvas);
    }

    @Override // android.widget.LinearLayout, android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        super.onLayout(z, i, i2, i3, i4);
        ValueAnimator valueAnimator = this.a;
        l lVar = this.b;
        if (valueAnimator != null && valueAnimator.isRunning()) {
            d(lVar.getSelectedTabPosition(), -1, false);
            return;
        }
        if (lVar.a == -1) {
            lVar.a = lVar.getSelectedTabPosition();
        }
        a(lVar.a);
    }

    @Override // android.widget.LinearLayout, android.view.View
    public final void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
        if (View.MeasureSpec.getMode(i) != 1073741824) {
            return;
        }
        l lVar = this.b;
        boolean z = true;
        if (lVar.z == 1 || lVar.C == 2) {
            int childCount = getChildCount();
            int iMax = 0;
            for (int i3 = 0; i3 < childCount; i3++) {
                View childAt = getChildAt(i3);
                if (childAt.getVisibility() == 0) {
                    iMax = Math.max(iMax, childAt.getMeasuredWidth());
                }
            }
            if (iMax <= 0) {
                return;
            }
            if (iMax * childCount <= getMeasuredWidth() - (((int) p.g(getContext(), 16)) * 2)) {
                boolean z2 = false;
                for (int i4 = 0; i4 < childCount; i4++) {
                    LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) getChildAt(i4).getLayoutParams();
                    if (layoutParams.width != iMax || layoutParams.weight != DefinitionKt.NO_Float_VALUE) {
                        layoutParams.width = iMax;
                        layoutParams.weight = DefinitionKt.NO_Float_VALUE;
                        z2 = true;
                    }
                }
                z = z2;
            } else {
                lVar.z = 0;
                lVar.q(false);
            }
            if (z) {
                super.onMeasure(i, i2);
            }
        }
    }
}
