package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import androidx.compose.ui.platform.ComposeView;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4708d;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends com.quizlet.baserecyclerview.c {
    public static final int f;
    public final ComposeView d;
    public final L e;

    static {
        g gVar = new g();
        int i = ComposeView.c;
        f = gVar.hashCode();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(ComposeView composeView, L l) {
        super(composeView);
        Intrinsics.checkNotNullParameter(composeView, "composeView");
        this.d = composeView;
        this.e = l;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        C4708d item = (C4708d) obj;
        Intrinsics.checkNotNullParameter(item, "item");
        this.d.setContent(new androidx.compose.runtime.internal.d(true, 623487252, new c(item, this, 1)));
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 21);
    }
}
