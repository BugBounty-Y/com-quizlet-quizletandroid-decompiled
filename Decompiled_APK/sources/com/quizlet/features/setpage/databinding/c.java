package com.quizlet.features.setpage.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.features.infra.legacyadapter.databinding.f;

/* loaded from: classes3.dex */
public final class c implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final f b;

    public c(ConstraintLayout constraintLayout, f fVar) {
        this.a = constraintLayout;
        this.b = fVar;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
