package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.appbar.CollapsingToolbarLayout;
import com.quizlet.partskit.widgets.QButton;

/* loaded from: classes3.dex */
public final class a0 implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final AppBarLayout b;
    public final QButton c;
    public final RecyclerView d;
    public final com.onetrust.otpublishers.headless.databinding.d e;
    public final CollapsingToolbarLayout f;

    public a0(ConstraintLayout constraintLayout, AppBarLayout appBarLayout, QButton qButton, RecyclerView recyclerView, com.onetrust.otpublishers.headless.databinding.d dVar, CollapsingToolbarLayout collapsingToolbarLayout) {
        this.a = constraintLayout;
        this.b = appBarLayout;
        this.c = qButton;
        this.d = recyclerView;
        this.e = dVar;
        this.f = collapsingToolbarLayout;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
