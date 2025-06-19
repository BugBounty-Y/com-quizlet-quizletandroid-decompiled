package com.quizlet.quizletandroid.ui.startpage.nav2.adapters;

import android.content.Context;
import android.view.ViewGroup;
import androidx.compose.ui.platform.ComposeView;
import androidx.recyclerview.widget.F0;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.AbstractC4707c;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4708d;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends a {
    public final L c;

    public f(L l) {
        super(AbstractC4178x.h("diffUtilCallback"));
        this.c = l;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        if (!(((AbstractC4707c) d(i)) instanceof C4708d)) {
            throw new IllegalArgumentException("Unsupported item type");
        }
        int i2 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.d.f;
        return com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.d.f;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.baserecyclerview.c holder = (com.quizlet.baserecyclerview.c) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        AbstractC4707c abstractC4707c = (AbstractC4707c) d(i);
        if (holder instanceof com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.d) {
            com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.d dVar = (com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.d) holder;
            Intrinsics.e(abstractC4707c, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.startpage.nav2.model.BrowseBySubjectData");
            C4708d item = (C4708d) abstractC4707c;
            dVar.getClass();
            Intrinsics.checkNotNullParameter(item, "item");
            dVar.d.setContent(new androidx.compose.runtime.internal.d(true, 623487252, new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.c(item, dVar, 1)));
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        if (i != com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.d.f) {
            throw new IllegalArgumentException("Unsupported item type");
        }
        Context context = parent.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        return new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.d(new ComposeView(context, null, 6), this.c);
    }
}
