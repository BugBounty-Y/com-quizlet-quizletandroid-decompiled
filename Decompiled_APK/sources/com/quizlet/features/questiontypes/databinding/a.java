package com.quizlet.features.questiontypes.databinding;

import android.view.View;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;

/* loaded from: classes3.dex */
public final class a implements androidx.viewbinding.a {
    public final /* synthetic */ int a;
    public final ConstraintLayout b;
    public final FrameLayout c;

    public /* synthetic */ a(ConstraintLayout constraintLayout, FrameLayout frameLayout, int i) {
        this.a = i;
        this.b = constraintLayout;
        this.c = frameLayout;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
        }
        return this.b;
    }
}
