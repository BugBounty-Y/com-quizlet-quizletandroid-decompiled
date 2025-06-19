package com.quizlet.features.infra.legacyadapter.databinding;

import android.view.View;
import android.widget.LinearLayout;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes3.dex */
public final class b implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final QTextView b;

    public b(LinearLayout linearLayout, QTextView qTextView) {
        this.a = linearLayout;
        this.b = qTextView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
