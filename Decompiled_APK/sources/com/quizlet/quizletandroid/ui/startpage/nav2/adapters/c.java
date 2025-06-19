package com.quizlet.quizletandroid.ui.startpage.nav2.adapters;

import androidx.compose.ui.platform.ComposeView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
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
        com.quizlet.quizletandroid.ui.startpage.nav2.model.r item = (com.quizlet.quizletandroid.ui.startpage.nav2.model.r) obj;
        Intrinsics.checkNotNullParameter(item, "item");
        this.d.setContent(new androidx.compose.runtime.internal.d(true, -1453977086, new b(item, 1)));
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 20);
    }
}
