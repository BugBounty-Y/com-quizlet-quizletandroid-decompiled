package com.braze.ui.contentcards.handlers;

import android.os.Parcelable;
import com.braze.events.ContentCardsUpdatedEvent;
import com.braze.models.cards.Card;
import java.util.List;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface IContentCardsUpdateHandler extends Parcelable {
    @NotNull
    List<Card> handleCardUpdate(@NotNull ContentCardsUpdatedEvent contentCardsUpdatedEvent);
}
