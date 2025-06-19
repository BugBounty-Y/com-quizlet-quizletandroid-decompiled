package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import androidx.compose.ui.platform.ComposeView;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.I;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p extends com.quizlet.baserecyclerview.c {
    public final com.quizlet.quizletandroid.ui.globalnav.composable.n d;
    public final ComposeView e;

    static {
        int i = ComposeView.c;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(com.quizlet.quizletandroid.ui.globalnav.composable.n onClick, ComposeView composeView) {
        super(composeView);
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        Intrinsics.checkNotNullParameter(composeView, "composeView");
        this.d = onClick;
        this.e = composeView;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        I item = (I) obj;
        Intrinsics.checkNotNullParameter(item, "item");
        this.e.setContent(new androidx.compose.runtime.internal.d(true, -1973590714, new o(this, 1)));
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 23);
    }
}
