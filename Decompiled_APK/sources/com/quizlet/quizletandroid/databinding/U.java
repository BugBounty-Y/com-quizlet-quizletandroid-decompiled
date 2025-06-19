package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.compose.ui.platform.ComposeView;

/* loaded from: classes3.dex */
public final class U implements androidx.viewbinding.a {
    public final ComposeView a;
    public final ComposeView b;

    public U(ComposeView composeView, ComposeView composeView2) {
        this.a = composeView;
        this.b = composeView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
