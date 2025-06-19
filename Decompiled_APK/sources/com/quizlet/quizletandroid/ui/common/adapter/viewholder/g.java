package com.quizlet.quizletandroid.ui.common.adapter.viewholder;

import android.view.View;
import android.widget.RelativeLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4612p;
import com.quizlet.quizletandroid.ui.diagramming.DiagramView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends com.quizlet.baserecyclerview.c {
    public io.reactivex.rxjava3.internal.observers.h d;

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        Void item = (Void) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.itemView;
        DiagramView diagramView = (DiagramView) AbstractC3375o2.c(R.id.diagram_view, view);
        if (diagramView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.diagram_view)));
        }
        C4612p c4612p = new C4612p((RelativeLayout) view, diagramView);
        Intrinsics.checkNotNullExpressionValue(c4612p, "bind(...)");
        return c4612p;
    }
}
