package com.braze.ui.contentcards.listeners;

import android.content.Context;
import com.braze.models.cards.Card;
import com.braze.ui.actions.IAction;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface IContentCardsActionListener {
    default boolean onContentCardClicked(@NotNull Context context, @NotNull Card card, IAction iAction) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(card, "card");
        return false;
    }

    default void onContentCardDismissed(@NotNull Context context, @NotNull Card card) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(card, "card");
    }
}
