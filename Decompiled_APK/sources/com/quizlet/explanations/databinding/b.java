package com.quizlet.explanations.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.FragmentContainerView;

/* loaded from: classes2.dex */
public final class b implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final FragmentContainerView b;

    public b(ConstraintLayout constraintLayout, FragmentContainerView fragmentContainerView) {
        this.a = constraintLayout;
        this.b = fragmentContainerView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
