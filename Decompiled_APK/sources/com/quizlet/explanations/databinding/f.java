package com.quizlet.explanations.databinding;

import android.view.View;
import androidx.fragment.app.FragmentContainerView;

/* loaded from: classes2.dex */
public final class f implements androidx.viewbinding.a {
    public final FragmentContainerView a;
    public final FragmentContainerView b;

    public f(FragmentContainerView fragmentContainerView, FragmentContainerView fragmentContainerView2) {
        this.a = fragmentContainerView;
        this.b = fragmentContainerView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
