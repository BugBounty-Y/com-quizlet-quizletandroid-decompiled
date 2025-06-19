package com.quizlet.quizletandroid.ui.startpage.nav2.adapters;

import android.content.Context;
import android.view.ViewGroup;
import androidx.compose.ui.platform.ComposeView;
import androidx.recyclerview.widget.F0;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.AbstractC4707c;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.M;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.O;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.t;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.u;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p extends a {
    public final L c;

    public p(L l) {
        super(AbstractC4178x.h("diffUtilCallback"));
        this.c = l;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        AbstractC4707c abstractC4707c = (AbstractC4707c) d(i);
        if (abstractC4707c instanceof O) {
            int i2 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f.e;
            return com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f.e;
        }
        if (!(abstractC4707c instanceof M)) {
            throw new IllegalArgumentException("Unsupported item type");
        }
        int i3 = u.f;
        return u.f;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.baserecyclerview.c holder = (com.quizlet.baserecyclerview.c) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        AbstractC4707c abstractC4707c = (AbstractC4707c) d(i);
        if (holder instanceof com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f) {
            Intrinsics.e(abstractC4707c, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.startpage.nav2.model.SectionHeaderHomeData");
            ((com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f) holder).g((O) abstractC4707c);
        } else if (holder instanceof u) {
            u uVar = (u) holder;
            Intrinsics.e(abstractC4707c, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.startpage.nav2.model.RevisionCenterData");
            M item = (M) abstractC4707c;
            uVar.getClass();
            Intrinsics.checkNotNullParameter(item, "item");
            uVar.d.setContent(new androidx.compose.runtime.internal.d(true, -781890917, new t(item, uVar, 1)));
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        if (i == com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f.e) {
            Context context = parent.getContext();
            Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
            return new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f(new ComposeView(context, null, 6));
        }
        if (i != u.f) {
            throw new IllegalArgumentException("Unsupported item type");
        }
        Context context2 = parent.getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
        return new u(new ComposeView(context2, null, 6), this.c);
    }
}
