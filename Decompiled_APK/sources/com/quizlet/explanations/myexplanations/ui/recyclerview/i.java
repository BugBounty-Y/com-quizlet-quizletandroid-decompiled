package com.quizlet.explanations.myexplanations.ui.recyclerview;

import androidx.compose.ui.platform.ComposeView;
import androidx.navigation.compose.o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class i extends com.quizlet.baserecyclerview.c {
    public final ComposeView d;

    static {
        int i = ComposeView.c;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(ComposeView composeView) {
        super(composeView);
        Intrinsics.checkNotNullParameter(composeView, "composeView");
        this.d = composeView;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        h item = (h) obj;
        Intrinsics.checkNotNullParameter(item, "item");
        this.d.setContent(new androidx.compose.runtime.internal.d(true, 1617951838, new o(14, item.a, item.b)));
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        return new c(this, 2);
    }
}
