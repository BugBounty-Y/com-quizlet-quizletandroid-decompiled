package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import androidx.compose.ui.platform.ComposeView;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.M;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u extends com.quizlet.baserecyclerview.c {
    public static final int f;
    public final ComposeView d;
    public final L e;

    static {
        g gVar = new g();
        int i = ComposeView.c;
        f = gVar.hashCode();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(ComposeView composeView, L l) {
        super(composeView);
        Intrinsics.checkNotNullParameter(composeView, "composeView");
        this.d = composeView;
        this.e = l;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        M item = (M) obj;
        Intrinsics.checkNotNullParameter(item, "item");
        this.d.setContent(new androidx.compose.runtime.internal.d(true, -781890917, new t(item, this, 1)));
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 24);
    }
}
