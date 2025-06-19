package com.braze.ui.contentcards.handlers;

import android.content.Context;
import android.os.Parcelable;
import android.view.ViewGroup;
import com.braze.models.cards.Card;
import com.braze.ui.contentcards.view.ContentCardViewHolder;
import java.util.List;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface IContentCardsViewBindingHandler extends Parcelable {
    int getItemViewType(@NotNull Context context, @NotNull List<? extends Card> list, int i);

    void onBindViewHolder(@NotNull Context context, @NotNull List<? extends Card> list, @NotNull ContentCardViewHolder contentCardViewHolder, int i);

    @NotNull
    ContentCardViewHolder onCreateViewHolder(@NotNull Context context, @NotNull List<? extends Card> list, @NotNull ViewGroup viewGroup, int i);
}
