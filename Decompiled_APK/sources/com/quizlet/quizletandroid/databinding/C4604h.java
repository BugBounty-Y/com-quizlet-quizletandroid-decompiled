package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QProgressBar;

/* renamed from: com.quizlet.quizletandroid.databinding.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4604h implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final com.onetrust.otpublishers.headless.databinding.b b;
    public final FrameLayout c;
    public final QProgressBar d;
    public final com.quizlet.features.infra.legacyadapter.databinding.f e;
    public final FrameLayout f;

    public C4604h(ConstraintLayout constraintLayout, com.onetrust.otpublishers.headless.databinding.b bVar, FrameLayout frameLayout, QProgressBar qProgressBar, com.quizlet.features.infra.legacyadapter.databinding.f fVar, FrameLayout frameLayout2) {
        this.a = constraintLayout;
        this.b = bVar;
        this.c = frameLayout;
        this.d = qProgressBar;
        this.e = fVar;
        this.f = frameLayout2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
