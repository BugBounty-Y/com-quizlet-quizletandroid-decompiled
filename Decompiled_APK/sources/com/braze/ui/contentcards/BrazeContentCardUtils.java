package com.braze.ui.contentcards;

import android.os.Bundle;
import androidx.camera.camera2.internal.a0;
import com.braze.models.cards.Card;
import com.braze.support.BrazeLogger;
import com.braze.triggers.managers.i;
import com.braze.ui.BrazeDeeplinkHandler;
import com.braze.ui.actions.UriAction;
import com.braze.ui.actions.brazeactions.BrazeActionUtils;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class BrazeContentCardUtils {

    @NotNull
    public static final BrazeContentCardUtils INSTANCE = new BrazeContentCardUtils();

    private BrazeContentCardUtils() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final int defaultCardHandling$lambda$0(Card cardA, Card cardB) {
        Intrinsics.checkNotNullParameter(cardA, "cardA");
        Intrinsics.checkNotNullParameter(cardB, "cardB");
        if (cardA.isPinned() && !cardB.isPinned()) {
            return -1;
        }
        if (!cardA.isPinned() && cardB.isPinned()) {
            return 1;
        }
        if (cardA.getCreated() > cardB.getCreated()) {
            return -1;
        }
        if (cardA.getCreated() < cardB.getCreated()) {
            return 1;
        }
        if (cardA.getId().compareTo(cardB.getId()) > 0) {
            return -1;
        }
        return cardA.getId().compareTo(cardB.getId()) < 0 ? 1 : 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getUriActionForCard$lambda$2() {
        return "Card URL is null, returning null for getUriActionForCard";
    }

    @NotNull
    public final List<Card> defaultCardHandling(@NotNull List<? extends Card> cards) {
        Intrinsics.checkNotNullParameter(cards, "cards");
        a0 a0Var = new a0(10);
        ArrayList arrayList = new ArrayList();
        for (Object obj : cards) {
            if (!BrazeActionUtils.containsInvalidBrazeAction((Card) obj)) {
                arrayList.add(obj);
            }
        }
        return CollectionsKt.n0(arrayList, a0Var);
    }

    public final UriAction getUriActionForCard(@NotNull Card card) {
        Intrinsics.checkNotNullParameter(card, "card");
        String url = card.getUrl();
        if (url == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new i(29), 6, (Object) null);
            return null;
        }
        Bundle bundle = new Bundle();
        for (String str : card.getExtras().keySet()) {
            bundle.putString(str, card.getExtras().get(str));
        }
        return BrazeDeeplinkHandler.Companion.getInstance().createUriActionFromUrlString(url, bundle, card.getOpenUriInWebView(), card.getChannel());
    }
}
