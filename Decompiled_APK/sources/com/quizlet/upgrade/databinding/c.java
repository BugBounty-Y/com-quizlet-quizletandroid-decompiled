package com.quizlet.upgrade.databinding;

import android.view.View;
import android.widget.ProgressBar;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import com.onetrust.otpublishers.headless.databinding.g;
import com.quizlet.features.infra.legacyadapter.databinding.f;

/* loaded from: classes3.dex */
public final class c implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final f b;
    public final View c;
    public final ProgressBar d;
    public final RecyclerView e;
    public final g f;

    public c(ConstraintLayout constraintLayout, f fVar, View view, ProgressBar progressBar, RecyclerView recyclerView, g gVar) {
        this.a = constraintLayout;
        this.b = fVar;
        this.c = view;
        this.d = progressBar;
        this.e = recyclerView;
        this.f = gVar;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
