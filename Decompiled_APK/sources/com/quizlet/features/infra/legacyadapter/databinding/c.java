package com.quizlet.features.infra.legacyadapter.databinding;

import android.view.View;
import android.widget.FrameLayout;
import com.quizlet.partskit.widgets.QButton;

/* loaded from: classes3.dex */
public final class c implements androidx.viewbinding.a {
    public final FrameLayout a;
    public final QButton b;

    public c(FrameLayout frameLayout, QButton qButton) {
        this.a = frameLayout;
        this.b = qButton;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
