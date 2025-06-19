package com.google.android.material.bottomappbar;

import android.graphics.Rect;
import android.graphics.RectF;
import android.view.View;
import android.view.ViewGroup;
import com.google.android.material.bottomappbar.BottomAppBar;
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.internal.p;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class e implements View.OnLayoutChangeListener {
    public final /* synthetic */ BottomAppBar.Behavior a;

    public e(BottomAppBar.Behavior behavior) {
        this.a = behavior;
    }

    @Override // android.view.View.OnLayoutChangeListener
    public final void onLayoutChange(View view, int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8) {
        BottomAppBar.Behavior behavior = this.a;
        BottomAppBar bottomAppBar = (BottomAppBar) behavior.k.get();
        if (bottomAppBar == null || !((view instanceof FloatingActionButton) || (view instanceof ExtendedFloatingActionButton))) {
            view.removeOnLayoutChangeListener(this);
            return;
        }
        int height = view.getHeight();
        if (view instanceof FloatingActionButton) {
            FloatingActionButton floatingActionButton = (FloatingActionButton) view;
            int measuredWidth = floatingActionButton.getMeasuredWidth();
            int measuredHeight = floatingActionButton.getMeasuredHeight();
            Rect rect = behavior.j;
            rect.set(0, 0, measuredWidth, measuredHeight);
            floatingActionButton.j(rect);
            int iHeight = rect.height();
            bottomAppBar.J(iHeight);
            bottomAppBar.setFabCornerSize(floatingActionButton.getShapeAppearanceModel().e.a(new RectF(rect)));
            height = iHeight;
        }
        androidx.coordinatorlayout.widget.e eVar = (androidx.coordinatorlayout.widget.e) view.getLayoutParams();
        if (behavior.l == 0) {
            if (bottomAppBar.n1 == 1) {
                ((ViewGroup.MarginLayoutParams) eVar).bottomMargin = bottomAppBar.getBottomInset() + (bottomAppBar.getResources().getDimensionPixelOffset(R.dimen.mtrl_bottomappbar_fab_bottom_margin) - ((view.getMeasuredHeight() - height) / 2));
            }
            ((ViewGroup.MarginLayoutParams) eVar).leftMargin = bottomAppBar.getLeftInset();
            ((ViewGroup.MarginLayoutParams) eVar).rightMargin = bottomAppBar.getRightInset();
            boolean zK = p.k(view);
            int i9 = bottomAppBar.o1;
            if (zK) {
                ((ViewGroup.MarginLayoutParams) eVar).leftMargin += i9;
            } else {
                ((ViewGroup.MarginLayoutParams) eVar).rightMargin += i9;
            }
        }
        int i10 = BottomAppBar.E1;
        bottomAppBar.I();
    }
}
