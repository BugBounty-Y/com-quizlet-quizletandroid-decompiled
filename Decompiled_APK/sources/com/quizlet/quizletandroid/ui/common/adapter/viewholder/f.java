package com.quizlet.quizletandroid.ui.common.adapter.viewholder;

import android.view.View;
import androidx.compose.ui.platform.ComposeView;
import com.quizlet.quizletandroid.databinding.X;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int e = 0;
    public final com.quizlet.features.settings.composables.dialogs.a d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(View itemView, com.quizlet.features.settings.composables.dialogs.a onClick) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        this.d = onClick;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.itemView;
        if (view == null) {
            throw new NullPointerException("rootView");
        }
        ComposeView composeView = (ComposeView) view;
        X x = new X(composeView, composeView);
        Intrinsics.checkNotNullExpressionValue(x, "bind(...)");
        return x;
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(com.quizlet.ui.models.content.carditem.a item) {
        Intrinsics.checkNotNullParameter(item, "item");
        ((X) e()).b.setContent(new androidx.compose.runtime.internal.d(true, 1029410826, new e(item, this, 1)));
    }
}
