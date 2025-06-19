package com.quizlet.quizletandroid.ui.activitycenter.adapters;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.F0;
import com.braze.ui.contentcards.adapters.EmptyContentCardsAdapter;
import com.quizlet.features.infra.legacyadapter.c;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends EmptyContentCardsAdapter {
    @Override // com.braze.ui.contentcards.adapters.EmptyContentCardsAdapter, androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return 1;
    }

    @Override // com.braze.ui.contentcards.adapters.EmptyContentCardsAdapter, androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_activity_center_empty_state, parent, false);
        Intrinsics.checkNotNullExpressionValue(view, "inflate(...)");
        Intrinsics.checkNotNullParameter(view, "view");
        return new c(view);
    }
}
