package com.braze.models.cards;

import androidx.compose.animation.d0;
import com.braze.enums.CardKey;
import com.braze.enums.CardType;
import com.braze.managers.c0;
import com.braze.storage.ICardStorageProvider;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class ControlCard extends Card {
    private final CardType cardType;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ControlCard(JSONObject jsonObject, CardKey.Provider cardKeysProvider, c0 c0Var, ICardStorageProvider<?> iCardStorageProvider, com.braze.analytics.c cVar) {
        super(jsonObject, cardKeysProvider, c0Var, iCardStorageProvider, cVar);
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        Intrinsics.checkNotNullParameter(cardKeysProvider, "cardKeysProvider");
        this.cardType = CardType.CONTROL;
    }

    @Override // com.braze.models.cards.Card
    public CardType getCardType() {
        return this.cardType;
    }

    @Override // com.braze.models.cards.Card
    public String toString() {
        return d0.r(new StringBuilder("ControlCard{"), super.toString(), '}');
    }
}
