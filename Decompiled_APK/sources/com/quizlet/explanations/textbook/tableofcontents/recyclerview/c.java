package com.quizlet.explanations.textbook.tableofcontents.recyclerview;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.explanations.databinding.o;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends com.quizlet.baserecyclerview.c {
    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        b item = (b) obj;
        Intrinsics.checkNotNullParameter(item, "item");
        QTextView qTextView = ((o) e()).b;
        item.getClass();
        qTextView.setText(R.string.chapter_header_title);
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.a;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.headerText, view);
        if (qTextView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.headerText)));
        }
        o oVar = new o((ConstraintLayout) view, qTextView);
        Intrinsics.checkNotNullExpressionValue(oVar, "bind(...)");
        return oVar;
    }
}
