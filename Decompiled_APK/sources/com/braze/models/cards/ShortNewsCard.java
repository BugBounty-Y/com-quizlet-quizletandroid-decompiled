package com.braze.models.cards;

import com.braze.enums.CardKey;
import com.braze.enums.CardType;
import com.braze.managers.c0;
import com.braze.storage.ICardStorageProvider;
import com.braze.support.JsonUtils;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.x;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class ShortNewsCard extends Card {
    private final CardType cardType;
    private final String description;
    private final String domain;
    private final String imageUrl;
    private final String title;
    private final String url;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ShortNewsCard(JSONObject jsonObject, CardKey.Provider cardKeyProvider, c0 c0Var, ICardStorageProvider<?> iCardStorageProvider, com.braze.analytics.c cVar) throws JSONException {
        super(jsonObject, cardKeyProvider, c0Var, iCardStorageProvider, cVar);
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        Intrinsics.checkNotNullParameter(cardKeyProvider, "cardKeyProvider");
        String string = jsonObject.getString(cardKeyProvider.getKey(CardKey.SHORT_NEWS_DESCRIPTION));
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        this.description = string;
        String string2 = jsonObject.getString(cardKeyProvider.getKey(CardKey.SHORT_NEWS_IMAGE));
        Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
        this.imageUrl = string2;
        this.title = JsonUtils.getOptionalString(jsonObject, cardKeyProvider.getKey(CardKey.SHORT_NEWS_TITLE));
        this.url = JsonUtils.getOptionalString(jsonObject, cardKeyProvider.getKey(CardKey.SHORT_NEWS_URL));
        this.domain = JsonUtils.getOptionalString(jsonObject, cardKeyProvider.getKey(CardKey.SHORT_NEWS_DOMAIN));
        this.cardType = CardType.SHORT_NEWS;
    }

    @Override // com.braze.models.cards.Card
    public CardType getCardType() {
        return this.cardType;
    }

    public final String getDescription() {
        return this.description;
    }

    public final String getDomain() {
        return this.domain;
    }

    public final String getImageUrl() {
        return this.imageUrl;
    }

    public final String getTitle() {
        return this.title;
    }

    @Override // com.braze.models.cards.Card
    public String getUrl() {
        return this.url;
    }

    @Override // com.braze.models.cards.Card
    public String toString() {
        return x.c("\n            ShortNewsCard{description='" + this.description + "'\n            imageUrl='" + this.imageUrl + "'\n            title='" + this.title + "'\n            url='" + getUrl() + "'\n            domain='" + this.domain + "\n            " + super.toString() + "}\n\n        ");
    }
}
