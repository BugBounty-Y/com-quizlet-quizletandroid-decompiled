package com.quizlet.explanations.questiondetail.recyclerview;

import androidx.compose.ui.platform.ComposeView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends com.quizlet.baserecyclerview.c {
    public final ComposeView d;

    static {
        int i = ComposeView.c;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(ComposeView composeView) {
        super(composeView);
        Intrinsics.checkNotNullParameter(composeView, "composeView");
        this.d = composeView;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        com.quizlet.explanations.questiondetail.data.e item = (com.quizlet.explanations.questiondetail.data.e) obj;
        Intrinsics.checkNotNullParameter(item, "item");
        this.d.setContent(new androidx.compose.runtime.internal.d(true, 322160228, new b(item, 1)));
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 3);
    }
}
