package com.quizlet.features.infra.legacyadapter.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;

/* loaded from: classes3.dex */
public final class a implements androidx.viewbinding.a {
    public final FrameLayout a;
    public final FrameLayout b;
    public final LinearLayout c;
    public final FrameLayout d;
    public final FrameLayout e;
    public final RecyclerView f;
    public final FrameLayout g;
    public final ProgressBar h;
    public final SwipeRefreshLayout i;

    public a(FrameLayout frameLayout, FrameLayout frameLayout2, LinearLayout linearLayout, FrameLayout frameLayout3, FrameLayout frameLayout4, RecyclerView recyclerView, FrameLayout frameLayout5, ProgressBar progressBar, SwipeRefreshLayout swipeRefreshLayout) {
        this.a = frameLayout;
        this.b = frameLayout2;
        this.c = linearLayout;
        this.d = frameLayout3;
        this.e = frameLayout4;
        this.f = recyclerView;
        this.g = frameLayout5;
        this.h = progressBar;
        this.i = swipeRefreshLayout;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
