package com.quizlet.explanations.databinding;

import android.view.View;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.fragment.app.FragmentContainerView;

/* loaded from: classes2.dex */
public final class e implements androidx.viewbinding.a {
    public final CoordinatorLayout a;
    public final FragmentContainerView b;

    public e(CoordinatorLayout coordinatorLayout, FragmentContainerView fragmentContainerView) {
        this.a = coordinatorLayout;
        this.b = fragmentContainerView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
