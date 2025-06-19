package com.quizlet.quizletandroid.ui.common.adapter.viewholder;

import android.view.View;
import android.widget.LinearLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.M;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends com.quizlet.baserecyclerview.c {
    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        Void item = (Void) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.itemView;
        int i = R.id.header_text_view;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.header_text_view, view);
        if (qTextView != null) {
            i = R.id.sort_container;
            LinearLayout linearLayout = (LinearLayout) AbstractC3375o2.c(R.id.sort_container, view);
            if (linearLayout != null) {
                i = R.id.sort_option_text_View;
                QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.sort_option_text_View, view);
                if (qTextView2 != null) {
                    M m = new M((LinearLayout) view, qTextView, linearLayout, qTextView2);
                    Intrinsics.checkNotNullExpressionValue(m, "bind(...)");
                    return m;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }
}
