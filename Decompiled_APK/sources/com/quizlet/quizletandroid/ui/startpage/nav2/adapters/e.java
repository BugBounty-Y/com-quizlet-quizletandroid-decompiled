package com.quizlet.quizletandroid.ui.startpage.nav2.adapters;

import android.content.Context;
import android.view.ViewGroup;
import androidx.compose.ui.platform.ComposeView;
import androidx.recyclerview.widget.F0;
import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.eventlogger.features.achievements.AchievementsEventLog;
import com.quizlet.eventlogger.features.achievements.AchievementsEventLogger;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.AbstractC4707c;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4705a;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.O;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends a {
    public final L c;
    public final com.quizlet.features.achievements.home.a d;

    public e(L l, com.quizlet.features.achievements.home.a aVar) {
        super(AbstractC4178x.h("diffUtilCallback"));
        this.c = l;
        this.d = aVar;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        AbstractC4707c abstractC4707c = (AbstractC4707c) d(i);
        if (abstractC4707c instanceof O) {
            return com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f.e;
        }
        if (!(abstractC4707c instanceof C4705a)) {
            throw new IllegalArgumentException("Unsupported item type");
        }
        int i2 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.b.e;
        return R.layout.nav2_listitem_achievements;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.baserecyclerview.c holder = (com.quizlet.baserecyclerview.c) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        AbstractC4707c abstractC4707c = (AbstractC4707c) d(i);
        if (holder instanceof com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f) {
            Intrinsics.e(abstractC4707c, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.startpage.nav2.model.SectionHeaderHomeData");
            ((com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f) holder).g((O) abstractC4707c);
            return;
        }
        if (holder instanceof com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.b) {
            Intrinsics.e(abstractC4707c, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.startpage.nav2.model.AchievementsHomeData");
            ((com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.b) holder).c((C4705a) abstractC4707c);
            com.quizlet.features.achievements.home.a aVar = this.d;
            if (aVar != null) {
                AchievementsEventLogger achievementsEventLogger = aVar.b;
                achievementsEventLogger.getClass();
                AchievementsEventLog.Companion companion = AchievementsEventLog.b;
                Z z = new Z(7);
                companion.getClass();
                achievementsEventLogger.a(AchievementsEventLog.Companion.a("achievements_progress_module_seen", z));
            }
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
        int i2 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.b.e;
        if (i == R.layout.nav2_listitem_achievements) {
            return new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.b(com.quizlet.baserecyclerview.b.g(parent, R.layout.nav2_listitem_achievements), new com.quizlet.login.magiclink.ui.e(this, 25));
        }
        throw new IllegalStateException(android.support.v4.media.session.a.f(i, "Can't find the ViewHolder for that viewType "));
    }
}
