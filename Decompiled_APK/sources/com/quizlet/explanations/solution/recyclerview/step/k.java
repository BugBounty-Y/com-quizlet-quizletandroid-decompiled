package com.quizlet.explanations.solution.recyclerview.step;

import androidx.compose.ui.platform.ComposeView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class k extends com.quizlet.baserecyclerview.c {
    public static final /* synthetic */ int f = 0;
    public final ComposeView d;
    public final com.quizlet.explanations.solution.viewmodel.b e;

    static {
        int i = ComposeView.c;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(ComposeView composeView, com.quizlet.explanations.solution.viewmodel.b renderListener) {
        super(composeView);
        Intrinsics.checkNotNullParameter(composeView, "composeView");
        Intrinsics.checkNotNullParameter(renderListener, "renderListener");
        this.d = composeView;
        this.e = renderListener;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        e item = (e) obj;
        Intrinsics.checkNotNullParameter(item, "item");
        this.d.setContent(new androidx.compose.runtime.internal.d(true, -609560868, new j(this, item, 1)));
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 6);
    }
}
