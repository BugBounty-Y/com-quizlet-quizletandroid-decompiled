package com.google.android.material.motion;

import android.content.res.Resources;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.view.V;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class i extends a {
    public final float g;
    public final float h;
    public final float i;

    public i(View view) {
        super(view);
        Resources resources = view.getResources();
        this.g = resources.getDimension(R.dimen.m3_back_progress_side_container_max_scale_x_distance_shrink);
        this.h = resources.getDimension(R.dimen.m3_back_progress_side_container_max_scale_x_distance_grow);
        this.i = resources.getDimension(R.dimen.m3_back_progress_side_container_max_scale_y_distance);
    }

    public final void b(float f, boolean z, int i) {
        float interpolation = this.a.getInterpolation(f);
        WeakHashMap weakHashMap = V.a;
        View view = this.b;
        boolean z2 = (Gravity.getAbsoluteGravity(i, view.getLayoutDirection()) & 3) == 3;
        boolean z3 = z == z2;
        int width = view.getWidth();
        int height = view.getHeight();
        float f2 = width;
        if (f2 > DefinitionKt.NO_Float_VALUE) {
            float f3 = height;
            if (f3 <= DefinitionKt.NO_Float_VALUE) {
                return;
            }
            float f4 = this.g / f2;
            float f5 = this.h / f2;
            float f6 = this.i / f3;
            if (z2) {
                f2 = 0.0f;
            }
            view.setPivotX(f2);
            if (!z3) {
                f5 = -f4;
            }
            float fA = com.google.android.material.animation.a.a(DefinitionKt.NO_Float_VALUE, f5, interpolation);
            float f7 = fA + 1.0f;
            view.setScaleX(f7);
            float fA2 = 1.0f - com.google.android.material.animation.a.a(DefinitionKt.NO_Float_VALUE, f6, interpolation);
            view.setScaleY(fA2);
            if (view instanceof ViewGroup) {
                ViewGroup viewGroup = (ViewGroup) view;
                for (int i2 = 0; i2 < viewGroup.getChildCount(); i2++) {
                    View childAt = viewGroup.getChildAt(i2);
                    childAt.setPivotX(z2 ? childAt.getWidth() + (width - childAt.getRight()) : -childAt.getLeft());
                    childAt.setPivotY(-childAt.getTop());
                    float f8 = z3 ? 1.0f - fA : 1.0f;
                    float f9 = fA2 != DefinitionKt.NO_Float_VALUE ? (f7 / fA2) * f8 : 1.0f;
                    childAt.setScaleX(f8);
                    childAt.setScaleY(f9);
                }
            }
        }
    }
}
