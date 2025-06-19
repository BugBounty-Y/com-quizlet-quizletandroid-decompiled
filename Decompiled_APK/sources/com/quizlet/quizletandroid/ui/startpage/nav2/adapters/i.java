package com.quizlet.quizletandroid.ui.startpage.nav2.adapters;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_barcode.G6;
import com.quizlet.assembly.compose.listitems.v;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.data.model.B0;
import com.quizlet.data.model.C0;
import com.quizlet.data.model.D0;
import com.quizlet.data.model.E0;
import com.quizlet.generated.enums.D;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.T;
import com.quizlet.quizletandroid.databinding.U;
import com.quizlet.quizletandroid.databinding.V;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.F;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends a {
    public final L c;

    public i(L l) {
        super(AbstractC4178x.h("diffUtilCallback"));
        this.c = l;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        B0 b0 = ((F) d(i)).d;
        if (b0 instanceof C0) {
            int i2 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.k.d;
            return R.layout.nav2_listitem_explanations_question;
        }
        if (b0 instanceof D0) {
            int i3 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.n.d;
            return R.layout.nav2_listitem_explanations_textbook;
        }
        if (b0 instanceof E0) {
            int i4 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.l.d;
            return R.layout.nav2_listitem_explanations_textbook_exercise;
        }
        timber.log.c.a.e(new IllegalStateException("Can't find viewType for that home data"));
        throw new IllegalStateException("Can't find viewType for that home data");
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        com.quizlet.baserecyclerview.c holder = (com.quizlet.baserecyclerview.c) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        F f = (F) d(i);
        if (holder instanceof com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.n) {
            Intrinsics.e(f, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.startpage.nav2.model.MyExplanationsHomeData");
            B0 b0 = f.d;
            Intrinsics.e(b0, "null cannot be cast to non-null type com.quizlet.data.model.MyExplanationsTextbook");
            D0 data = (D0) b0;
            com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.n nVar = (com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.n) holder;
            com.quizlet.features.questionnaire.screens.c onClick = new com.quizlet.features.questionnaire.screens.c(26, this, data);
            nVar.getClass();
            Intrinsics.checkNotNullParameter(data, "data");
            Intrinsics.checkNotNullParameter(onClick, "onClick");
            ((U) nVar.e()).b.setContent(new androidx.compose.runtime.internal.d(true, -257691514, new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.m(new com.quizlet.ui.models.content.carditem.g(data.h, data.a, data.b, data.c, data.e, data.i, data.d, data.f, f.e), onClick, 1)));
            return;
        }
        if (!(holder instanceof com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.k)) {
            if (holder instanceof com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.l) {
                Intrinsics.e(f, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.startpage.nav2.model.MyExplanationsHomeData");
                B0 b02 = f.d;
                Intrinsics.e(b02, "null cannot be cast to non-null type com.quizlet.data.model.MyExplanationsTextbookExercise");
                E0 data2 = (E0) b02;
                com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.l lVar = (com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.l) holder;
                com.quizlet.features.questionnaire.screens.c onClick2 = new com.quizlet.features.questionnaire.screens.c(28, this, data2);
                lVar.getClass();
                Intrinsics.checkNotNullParameter(data2, "data");
                Intrinsics.checkNotNullParameter(onClick2, "onClick");
                ((V) lVar.e()).b.setContent(new androidx.compose.runtime.internal.d(true, 313592990, new v(data2, f.e, onClick2, 3)));
                return;
            }
            return;
        }
        Intrinsics.e(f, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.startpage.nav2.model.MyExplanationsHomeData");
        B0 b03 = f.d;
        Intrinsics.e(b03, "null cannot be cast to non-null type com.quizlet.data.model.MyExplanationsQuestion");
        C0 data3 = (C0) b03;
        com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.k kVar = (com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.k) holder;
        com.quizlet.features.questionnaire.screens.c onClick3 = new com.quizlet.features.questionnaire.screens.c(27, this, data3);
        kVar.getClass();
        Intrinsics.checkNotNullParameter(data3, "data");
        Intrinsics.checkNotNullParameter(onClick3, "onClick");
        D d = (D) CollectionsKt.firstOrNull(data3.e);
        ((T) kVar.e()).b.setContent(new androidx.compose.runtime.internal.d(true, -480176234, new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.j(new com.quizlet.ui.models.content.carditem.e(data3.d, data3.g, data3.b, d != null ? Integer.valueOf(G6.d(d)) : null, f.e), onClick3, 1)));
        holder.itemView.setTag(R.id.unifiedRecyclerView, Boolean.valueOf(f.a));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View itemView = LayoutInflater.from(parent.getContext()).inflate(i, parent, false);
        int i2 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.n.d;
        if (i == R.layout.nav2_listitem_explanations_textbook) {
            Intrinsics.d(itemView);
            a.h(itemView);
            Intrinsics.checkNotNullParameter(itemView, "itemView");
            return new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.n(itemView);
        }
        int i3 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.k.d;
        if (i == R.layout.nav2_listitem_explanations_question) {
            Intrinsics.d(itemView);
            a.h(itemView);
            Intrinsics.checkNotNullParameter(itemView, "itemView");
            return new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.k(itemView);
        }
        int i4 = com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.l.d;
        if (i != R.layout.nav2_listitem_explanations_textbook_exercise) {
            timber.log.c.a.e(new IllegalStateException("Can't find the ViewHolder for that viewType"));
            throw new IllegalStateException("Can't find the ViewHolder for that viewType");
        }
        Intrinsics.d(itemView);
        a.h(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        return new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.l(itemView);
    }
}
