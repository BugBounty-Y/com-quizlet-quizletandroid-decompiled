package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import androidx.compose.ui.platform.ComposeView;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import com.google.android.material.floatingactionbutton.FloatingActionButton;

/* renamed from: com.quizlet.quizletandroid.databinding.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4600d implements androidx.viewbinding.a {
    public final FrameLayout a;
    public final FloatingActionButton b;
    public final com.quizlet.features.infra.legacyadapter.databinding.h c;
    public final ComposeView d;
    public final CoordinatorLayout e;
    public final FrameLayout f;
    public final RelativeLayout g;
    public final FrameLayout h;

    public C4600d(FrameLayout frameLayout, FloatingActionButton floatingActionButton, com.quizlet.features.infra.legacyadapter.databinding.h hVar, ComposeView composeView, CoordinatorLayout coordinatorLayout, FrameLayout frameLayout2, RelativeLayout relativeLayout, FrameLayout frameLayout3) {
        this.a = frameLayout;
        this.b = floatingActionButton;
        this.c = hVar;
        this.d = composeView;
        this.e = coordinatorLayout;
        this.f = frameLayout2;
        this.g = relativeLayout;
        this.h = frameLayout3;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
