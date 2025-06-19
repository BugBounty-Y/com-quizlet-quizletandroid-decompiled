package com.quizlet.explanations.solution.solutionwall;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.ui.platform.ComposeView;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a extends com.quizlet.baserecyclerview.b {
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        b bVar = (b) d(i);
        if (bVar instanceof g) {
            com.google.firebase.heartbeatinfo.e eVar = c.a;
            return 0;
        }
        if (bVar instanceof i) {
            com.google.firebase.heartbeatinfo.e eVar2 = c.a;
            return 1;
        }
        if (!(bVar instanceof d)) {
            throw new NoWhenBranchMatchedException();
        }
        com.google.firebase.heartbeatinfo.e eVar3 = c.a;
        return 2;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.baserecyclerview.c holder = (com.quizlet.baserecyclerview.c) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        b bVar = (b) d(i);
        if (holder instanceof h) {
            Intrinsics.e(bVar, "null cannot be cast to non-null type com.quizlet.explanations.solution.solutionwall.PaywallItem");
            ((h) holder).c((g) bVar);
            return;
        }
        if (holder instanceof k) {
            Intrinsics.e(bVar, "null cannot be cast to non-null type com.quizlet.explanations.solution.solutionwall.SignUpWallItem");
            ((k) holder).c((i) bVar);
        } else if (holder instanceof com.quizlet.explanations.solution.solutionwall.limitedcontent.d) {
            com.quizlet.explanations.solution.solutionwall.limitedcontent.d dVar = (com.quizlet.explanations.solution.solutionwall.limitedcontent.d) holder;
            Intrinsics.e(bVar, "null cannot be cast to non-null type com.quizlet.explanations.solution.solutionwall.LimitedContentWallItem");
            d item = (d) bVar;
            dVar.getClass();
            Intrinsics.checkNotNullParameter(item, "item");
            dVar.d.setContent(new androidx.compose.runtime.internal.d(true, -1795981744, new com.quizlet.explanations.solution.solutionwall.limitedcontent.c(item, 1)));
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        c cVar;
        Intrinsics.checkNotNullParameter(parent, "parent");
        c.a.getClass();
        c[] cVarArrValues = c.values();
        int length = cVarArrValues.length;
        int i2 = 0;
        while (true) {
            if (i2 >= length) {
                cVar = null;
                break;
            }
            cVar = cVarArrValues[i2];
            if (cVar.ordinal() == i) {
                break;
            }
            i2++;
        }
        if (cVar == null) {
            throw new IllegalArgumentException("Invalid ExplanationsSolutionWallType");
        }
        int iOrdinal = cVar.ordinal();
        if (iOrdinal == 0) {
            View itemView = com.quizlet.baserecyclerview.b.g(parent, R.layout.explanations_metering_paywall);
            Intrinsics.checkNotNullParameter(itemView, "itemView");
            return new h(itemView);
        }
        if (iOrdinal == 1) {
            View itemView2 = com.quizlet.baserecyclerview.b.g(parent, R.layout.listitem_explanations_sign_up_wall);
            Intrinsics.checkNotNullParameter(itemView2, "itemView");
            return new k(itemView2);
        }
        if (iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        Context context = parent.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        return new com.quizlet.explanations.solution.solutionwall.limitedcontent.d(new ComposeView(context, null, 6));
    }
}
