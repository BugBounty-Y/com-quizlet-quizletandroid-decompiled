package com.quizlet.quizletandroid.ui.startpage.nav2.adapters;

import android.content.Context;
import android.view.ViewGroup;
import androidx.compose.ui.platform.ComposeView;
import androidx.recyclerview.widget.F0;
import com.onetrust.otpublishers.headless.UI.adapter.s;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.AbstractC4707c;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.E;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.O;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.u;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q extends a {
    public final Y c;
    public final r d;

    public q(Y setNavDelegate, Y homeScrollDelegate, Y studiableLoggingDelegate, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager) {
        Intrinsics.checkNotNullParameter(setNavDelegate, "setNavDelegate");
        Intrinsics.checkNotNullParameter(homeScrollDelegate, "homeScrollDelegate");
        Intrinsics.checkNotNullParameter(studiableLoggingDelegate, "studiableLoggingDelegate");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        s diffUtilCallback = new s(2);
        Intrinsics.checkNotNullParameter(diffUtilCallback, "diffUtilCallback");
        super(diffUtilCallback);
        this.c = homeScrollDelegate;
        this.d = new r(setNavDelegate, studiableLoggingDelegate, loggedInUserManager, -1);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        AbstractC4707c abstractC4707c = (AbstractC4707c) d(i);
        if (abstractC4707c instanceof O) {
            return com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f.e;
        }
        if (!(abstractC4707c instanceof E)) {
            throw new IllegalArgumentException("Unsupported item type");
        }
        int i2 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.i.d;
        return R.layout.nav2_horizontal_model_holder;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.baserecyclerview.c holder = (com.quizlet.baserecyclerview.c) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        AbstractC4707c abstractC4707c = (AbstractC4707c) d(i);
        if (holder instanceof com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f) {
            Intrinsics.e(abstractC4707c, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.startpage.nav2.model.SectionHeaderHomeData");
            ((com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f) holder).g((O) abstractC4707c);
        } else if (holder instanceof com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.i) {
            Intrinsics.e(abstractC4707c, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.startpage.nav2.model.HorizontalStudySetHomeData");
            E e = (E) abstractC4707c;
            ((com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.i) holder).f(u.g, this.c, e.f(), new com.quizlet.features.setpage.header.ui.g(23, this, e));
            holder.itemView.setTag(R.id.unifiedRecyclerView, Boolean.valueOf(e.a));
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
        int i2 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.i.d;
        if (i == R.layout.nav2_horizontal_model_holder) {
            return new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.i(com.quizlet.baserecyclerview.b.g(parent, i));
        }
        timber.log.c.a.e(new IllegalStateException("Can't find the ViewHolder for that viewType"));
        throw new IllegalStateException("Can't find the ViewHolder for that viewType");
    }
}
