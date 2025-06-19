package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;

/* loaded from: classes3.dex */
public final class L implements androidx.viewbinding.a {
    public final /* synthetic */ int a;
    public final FrameLayout b;
    public final FrameLayout c;

    public /* synthetic */ L(FrameLayout frameLayout, FrameLayout frameLayout2, int i) {
        this.a = i;
        this.b = frameLayout;
        this.c = frameLayout2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
        }
        return this.b;
    }
}
