package com.quizlet.quizletandroid.ui.common.adapter;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.cardview.widget.CardView;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.K;
import java.text.DecimalFormat;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlin.u;

/* loaded from: classes3.dex */
public final class a extends AbstractC1361d0 {
    public final List a;

    public a(List highScoreInfos) {
        Intrinsics.checkNotNullParameter(highScoreInfos, "highScoreInfos");
        this.a = highScoreInfos;
        setHasStableIds(true);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.a.size();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final long getItemId(int i) {
        return ((com.quizlet.features.match.highscore.a) this.a.get(i)).e;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.quizletandroid.ui.common.adapter.viewholder.b holder = (com.quizlet.quizletandroid.ui.common.adapter.viewholder.b) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        com.quizlet.features.match.highscore.a highScoreInfo = (com.quizlet.features.match.highscore.a) this.a.get(i);
        holder.getClass();
        Intrinsics.checkNotNullParameter(highScoreInfo, "highScoreInfo");
        com.quizlet.infra.legacysyncengine.managers.d dVar = holder.b;
        if (dVar == null) {
            Intrinsics.m("loggedInUserManager");
            throw null;
        }
        DBUser dBUser = dVar.r;
        com.quizlet.quizletandroid.ui.common.adapter.viewholder.a aVar = (dBUser == null || dBUser.getId() != highScoreInfo.e) ? com.quizlet.quizletandroid.ui.common.adapter.viewholder.a.f : com.quizlet.quizletandroid.ui.common.adapter.viewholder.a.g;
        View view = holder.itemView;
        LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(-1, holder.c(aVar.a));
        int i2 = aVar.c;
        layoutParams.setMarginStart(holder.c(i2));
        layoutParams.setMarginEnd(holder.c(i2));
        layoutParams.topMargin = i != 0 ? 0 : holder.c(R.dimen.leaderboard_margin_top);
        layoutParams.bottomMargin = holder.c(R.dimen.leaderboard_margin_bottom);
        view.setLayoutParams(layoutParams);
        View view2 = holder.itemView;
        Intrinsics.e(view2, "null cannot be cast to non-null type androidx.cardview.widget.CardView");
        ((CardView) view2).setCardElevation(holder.c(aVar.b));
        u uVar = holder.c;
        QTextView leaderboardTime = ((K) uVar.getValue()).d;
        Intrinsics.checkNotNullExpressionValue(leaderboardTime, "leaderboardTime");
        ViewGroup.LayoutParams layoutParams2 = leaderboardTime.getLayoutParams();
        Intrinsics.e(layoutParams2, "null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
        ((ViewGroup.MarginLayoutParams) layoutParams2).setMarginStart(holder.c(aVar.e));
        QTextView leaderboardRanking = ((K) uVar.getValue()).c;
        Intrinsics.checkNotNullExpressionValue(leaderboardRanking, "leaderboardRanking");
        leaderboardRanking.getLayoutParams().width = holder.c(aVar.d);
        QTextView leaderboardRanking2 = ((K) uVar.getValue()).c;
        Intrinsics.checkNotNullExpressionValue(leaderboardRanking2, "leaderboardRanking");
        leaderboardRanking2.setText(String.valueOf(highScoreInfo.d + 1));
        QTextView leaderboardTime2 = ((K) uVar.getValue()).d;
        Intrinsics.checkNotNullExpressionValue(leaderboardTime2, "leaderboardTime");
        leaderboardTime2.setText(holder.itemView.getContext().getString(R.string.match_leaderboard_number_with_seconds, new DecimalFormat("0.0").format(highScoreInfo.b / 10.0d)));
        QTextView leaderboardUsername = ((K) uVar.getValue()).e;
        Intrinsics.checkNotNullExpressionValue(leaderboardUsername, "leaderboardUsername");
        leaderboardUsername.setText(highScoreInfo.a);
        String str = highScoreInfo.c;
        if (str == null || StringsKt.O(str)) {
            ImageView leaderboardProfilepic = ((K) uVar.getValue()).b;
            Intrinsics.checkNotNullExpressionValue(leaderboardProfilepic, "leaderboardProfilepic");
            leaderboardProfilepic.setImageDrawable(null);
            return;
        }
        com.quizlet.qutils.image.loading.a aVar2 = holder.a;
        if (aVar2 == null) {
            Intrinsics.m("imageLoader");
            throw null;
        }
        com.quizlet.data.repository.widget.b bVarP = ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) aVar2).a(holder.itemView.getContext()).p(str);
        bVarP.d();
        ImageView leaderboardProfilepic2 = ((K) uVar.getValue()).b;
        Intrinsics.checkNotNullExpressionValue(leaderboardProfilepic2, "leaderboardProfilepic");
        bVarP.o(leaderboardProfilepic2);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(parent.getContext());
        int i2 = com.quizlet.quizletandroid.ui.common.adapter.viewholder.b.d;
        View viewInflate = layoutInflaterFrom.inflate(R.layout.leaderboard_score_item, parent, false);
        Intrinsics.d(viewInflate);
        return new com.quizlet.quizletandroid.ui.common.adapter.viewholder.b(viewInflate);
    }
}
