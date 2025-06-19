package com.quizlet.explanations.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.fragment.app.FragmentContainerView;

/* loaded from: classes2.dex */
public final class g implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final FrameLayout b;
    public final FragmentContainerView c;

    public g(LinearLayout linearLayout, FrameLayout frameLayout, FragmentContainerView fragmentContainerView) {
        this.a = linearLayout;
        this.b = frameLayout;
        this.c = fragmentContainerView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
