package com.quizlet.features.infra.legacyadapter.viewholder;

import android.view.View;
import android.widget.FrameLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int d = 0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(View itemView) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        Void item = (Void) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.itemView;
        QButton qButton = (QButton) AbstractC3375o2.c(R.id.top_button, view);
        if (qButton == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.top_button)));
        }
        com.quizlet.features.infra.legacyadapter.databinding.c cVar = new com.quizlet.features.infra.legacyadapter.databinding.c((FrameLayout) view, qButton);
        Intrinsics.checkNotNullExpressionValue(cVar, "bind(...)");
        return cVar;
    }
}
