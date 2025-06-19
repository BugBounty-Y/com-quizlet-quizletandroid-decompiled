package com.quizlet.explanations.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QTabLayout;

/* loaded from: classes2.dex */
public final class v implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final QTabLayout b;

    public v(ConstraintLayout constraintLayout, QTabLayout qTabLayout) {
        this.a = constraintLayout;
        this.b = qTabLayout;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
