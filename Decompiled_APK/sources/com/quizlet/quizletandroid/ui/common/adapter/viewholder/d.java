package com.quizlet.quizletandroid.ui.common.adapter.viewholder;

import android.view.View;
import androidx.compose.ui.platform.ComposeView;
import com.quizlet.quizletandroid.databinding.W;
import com.quizlet.quizletandroid.ui.common.ads.G;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int e = 0;
    public final G d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(View itemView, G onClick) {
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
        W w = new W(composeView, composeView);
        Intrinsics.checkNotNullExpressionValue(w, "bind(...)");
        return w;
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(com.quizlet.ui.models.content.carditem.c item) {
        Intrinsics.checkNotNullParameter(item, "item");
        ((W) e()).b.setContent(new androidx.compose.runtime.internal.d(true, -195637231, new c(item, this, 1)));
    }
}
