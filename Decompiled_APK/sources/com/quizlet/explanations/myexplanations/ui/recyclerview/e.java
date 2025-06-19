package com.quizlet.explanations.myexplanations.ui.recyclerview;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.explanations.databinding.w;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e extends com.quizlet.baserecyclerview.c {
    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        com.quizlet.explanations.myexplanations.data.h item = (com.quizlet.explanations.myexplanations.data.h) obj;
        Intrinsics.checkNotNullParameter(item, "item");
        ((w) e()).b.setText(item.b);
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.headerText, view);
        if (qTextView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.headerText)));
        }
        w wVar = new w((ConstraintLayout) view, qTextView);
        Intrinsics.checkNotNullExpressionValue(wVar, "bind(...)");
        return wVar;
    }
}
