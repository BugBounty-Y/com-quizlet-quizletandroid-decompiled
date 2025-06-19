package com.google.android.material.snackbar;

import android.animation.AnimatorSet;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.os.Build;
import android.util.Log;
import android.view.Display;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.WindowManager;
import com.google.android.material.internal.p;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class d implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ g b;

    public /* synthetic */ d(g gVar, int i) {
        this.a = i;
        this.b = gVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        Rect rect;
        g gVar = this.b;
        int i = 1;
        byte b = 0;
        switch (this.a) {
            case 0:
                if (gVar.i != null) {
                    Context context = gVar.h;
                    int i2 = p.d;
                    WindowManager windowManager = (WindowManager) context.getSystemService("window");
                    if (Build.VERSION.SDK_INT >= 30) {
                        rect = windowManager.getCurrentWindowMetrics().getBounds();
                    } else {
                        Display defaultDisplay = windowManager.getDefaultDisplay();
                        Point point = new Point();
                        defaultDisplay.getRealSize(point);
                        rect = new Rect();
                        rect.right = point.x;
                        rect.bottom = point.y;
                    }
                    int iHeight = rect.height();
                    int[] iArr = new int[2];
                    f fVar = gVar.i;
                    fVar.getLocationInWindow(iArr);
                    int height = (iHeight - (fVar.getHeight() + iArr[1])) + ((int) fVar.getTranslationY());
                    int i3 = gVar.p;
                    if (height < i3) {
                        ViewGroup.LayoutParams layoutParams = fVar.getLayoutParams();
                        if (!(layoutParams instanceof ViewGroup.MarginLayoutParams)) {
                            Log.w(g.A, "Unable to apply gesture inset because layout params are not MarginLayoutParams");
                            break;
                        } else {
                            int i4 = gVar.p;
                            gVar.q = i4;
                            ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
                            marginLayoutParams.bottomMargin = (i4 - height) + marginLayoutParams.bottomMargin;
                            fVar.requestLayout();
                            break;
                        }
                    } else {
                        gVar.q = i3;
                        break;
                    }
                }
                break;
            case 1:
                gVar.c(3);
                break;
            default:
                f fVar2 = gVar.i;
                if (fVar2 != null) {
                    ViewParent parent = fVar2.getParent();
                    f fVar3 = gVar.i;
                    if (parent != null) {
                        fVar3.setVisibility(0);
                    }
                    if (fVar3.getAnimationMode() != 1) {
                        int height2 = fVar3.getHeight();
                        ViewGroup.LayoutParams layoutParams2 = fVar3.getLayoutParams();
                        if (layoutParams2 instanceof ViewGroup.MarginLayoutParams) {
                            height2 += ((ViewGroup.MarginLayoutParams) layoutParams2).bottomMargin;
                        }
                        fVar3.setTranslationY(height2);
                        ValueAnimator valueAnimator = new ValueAnimator();
                        valueAnimator.setIntValues(height2, 0);
                        valueAnimator.setInterpolator(gVar.e);
                        valueAnimator.setDuration(gVar.c);
                        valueAnimator.addListener(new c(gVar, b));
                        valueAnimator.addUpdateListener(new b(gVar, height2));
                        valueAnimator.start();
                        break;
                    } else {
                        ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(DefinitionKt.NO_Float_VALUE, 1.0f);
                        valueAnimatorOfFloat.setInterpolator(gVar.d);
                        valueAnimatorOfFloat.addUpdateListener(new b(gVar, b, b));
                        ValueAnimator valueAnimatorOfFloat2 = ValueAnimator.ofFloat(0.8f, 1.0f);
                        valueAnimatorOfFloat2.setInterpolator(gVar.f);
                        valueAnimatorOfFloat2.addUpdateListener(new b(gVar, i, b));
                        AnimatorSet animatorSet = new AnimatorSet();
                        animatorSet.playTogether(valueAnimatorOfFloat, valueAnimatorOfFloat2);
                        animatorSet.setDuration(gVar.a);
                        animatorSet.addListener(new c(gVar, i));
                        animatorSet.start();
                        break;
                    }
                }
                break;
        }
    }
}
