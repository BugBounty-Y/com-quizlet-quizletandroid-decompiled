package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import com.quizlet.quizletandroid.ui.common.views.ToggleSwipeableViewPager;

/* loaded from: classes3.dex */
public final class H implements androidx.viewbinding.a {
    public final CoordinatorLayout a;
    public final com.quizlet.features.infra.legacyadapter.databinding.f b;
    public final CoordinatorLayout c;
    public final ToggleSwipeableViewPager d;

    public H(CoordinatorLayout coordinatorLayout, com.quizlet.features.infra.legacyadapter.databinding.f fVar, CoordinatorLayout coordinatorLayout2, ToggleSwipeableViewPager toggleSwipeableViewPager) {
        this.a = coordinatorLayout;
        this.b = fVar;
        this.c = coordinatorLayout2;
        this.d = toggleSwipeableViewPager;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
