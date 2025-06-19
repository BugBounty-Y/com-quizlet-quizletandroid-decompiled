package com.braze.ui.contentcards.adapters;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.braze.ui.R$layout;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class EmptyContentCardsAdapter extends AbstractC1361d0 {

    @Metadata
    public static final class NetworkUnavailableViewHolder extends F0 {
        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public NetworkUnavailableViewHolder(@NotNull View view) {
            super(view);
            Intrinsics.checkNotNullParameter(view, "view");
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public int getItemCount() {
        return 1;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public void onBindViewHolder(@NotNull F0 viewHolder, int i) {
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    @NotNull
    public F0 onCreateViewHolder(@NotNull ViewGroup viewGroup, int i) {
        Intrinsics.checkNotNullParameter(viewGroup, "viewGroup");
        View viewInflate = LayoutInflater.from(viewGroup.getContext()).inflate(R$layout.com_braze_content_cards_empty, viewGroup, false);
        Intrinsics.d(viewInflate);
        return new NetworkUnavailableViewHolder(viewInflate);
    }
}
