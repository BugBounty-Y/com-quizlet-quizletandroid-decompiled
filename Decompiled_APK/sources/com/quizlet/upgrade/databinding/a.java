package com.quizlet.upgrade.databinding;

import android.view.View;
import androidx.appcompat.widget.Toolbar;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.FragmentContainerView;

/* loaded from: classes3.dex */
public final class a implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final FragmentContainerView b;
    public final Toolbar c;

    public a(ConstraintLayout constraintLayout, FragmentContainerView fragmentContainerView, Toolbar toolbar) {
        this.a = constraintLayout;
        this.b = fragmentContainerView;
        this.c = toolbar;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
