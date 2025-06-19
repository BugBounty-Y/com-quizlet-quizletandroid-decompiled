package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.appcompat.widget.Toolbar;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.appbar.AppBarLayout;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class J implements androidx.viewbinding.a {
    public final /* synthetic */ int a;
    public final AppBarLayout b;
    public final Toolbar c;

    public /* synthetic */ J(AppBarLayout appBarLayout, Toolbar toolbar, int i) {
        this.a = i;
        this.b = appBarLayout;
        this.c = toolbar;
    }

    public static J a(View view) {
        AppBarLayout appBarLayout = (AppBarLayout) view;
        Toolbar toolbar = (Toolbar) AbstractC3375o2.c(R.id.toolbar, view);
        if (toolbar != null) {
            return new J(appBarLayout, toolbar, 0);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.toolbar)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
        }
        return this.b;
    }
}
