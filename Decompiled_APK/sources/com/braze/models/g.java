package com.braze.models;

import androidx.core.view.C;
import androidx.navigation.compose.C1277j;
import com.braze.enums.CardKey;
import com.braze.enums.CardType;
import com.braze.managers.C1500m;
import com.braze.managers.c0;
import com.braze.models.cards.CaptionedImageCard;
import com.braze.models.cards.Card;
import com.braze.models.cards.ControlCard;
import com.braze.models.cards.ImageOnlyCard;
import com.braze.models.cards.ShortNewsCard;
import com.braze.models.cards.TextAnnouncementCard;
import com.braze.storage.ICardStorageProvider;
import com.braze.support.BrazeLogger;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.q;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class g {
    public static final g a = new g();

    public static final Card a(CardKey.Provider provider, c0 c0Var, ICardStorageProvider iCardStorageProvider, com.braze.analytics.c cVar, JSONArray jSONArray, Object it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        try {
            return a(new JSONObject(it2.toString()), provider, c0Var, iCardStorageProvider, cVar);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new C1277j(11, it2, jSONArray), 4, (Object) null);
            return null;
        }
    }

    public static final String a(Object obj, JSONArray jSONArray) {
        return "Unable to create Card JSON in array. Ignoring. Was on element: " + obj + " of json array: " + jSONArray;
    }

    public static final Card a(JSONObject jsonObject, CardKey.Provider cardKeyProvider, c0 brazeManager, ICardStorageProvider cardStorageProvider, com.braze.analytics.c cardAnalyticsProvider) {
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        Intrinsics.checkNotNullParameter(cardKeyProvider, "cardKeyProvider");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        Intrinsics.checkNotNullParameter(cardStorageProvider, "cardStorageProvider");
        Intrinsics.checkNotNullParameter(cardAnalyticsProvider, "cardAnalyticsProvider");
        CardType cardTypeFromJson = cardKeyProvider.getCardTypeFromJson(jsonObject);
        int i = cardTypeFromJson == null ? -1 : d.a[cardTypeFromJson.ordinal()];
        if (i == 1) {
            return new ImageOnlyCard(jsonObject, cardKeyProvider, brazeManager, cardStorageProvider, cardAnalyticsProvider);
        }
        if (i == 2) {
            return new CaptionedImageCard(jsonObject, cardKeyProvider, brazeManager, cardStorageProvider, cardAnalyticsProvider);
        }
        if (i == 3) {
            return new ShortNewsCard(jsonObject, cardKeyProvider, brazeManager, cardStorageProvider, cardAnalyticsProvider);
        }
        if (i == 4) {
            return new TextAnnouncementCard(jsonObject, cardKeyProvider, brazeManager, cardStorageProvider, cardAnalyticsProvider);
        }
        if (i != 5) {
            return null;
        }
        return new ControlCard(jsonObject, cardKeyProvider, brazeManager, cardStorageProvider, cardAnalyticsProvider);
    }

    public static final List a(JSONArray cardJsonStringArray, CardKey.Provider cardKeyProvider, C1500m brazeManager, ICardStorageProvider cardStorageProvider, com.braze.analytics.c cardAnalyticsProvider) {
        Intrinsics.checkNotNullParameter(cardJsonStringArray, "cardJsonStringArray");
        Intrinsics.checkNotNullParameter(cardKeyProvider, "cardKeyProvider");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        Intrinsics.checkNotNullParameter(cardStorageProvider, "cardStorageProvider");
        Intrinsics.checkNotNullParameter(cardAnalyticsProvider, "cardAnalyticsProvider");
        return q.j(q.i(kotlin.sequences.n.b(new C(q.h(q.e(CollectionsKt.D(kotlin.ranges.l.h(0, cardJsonStringArray.length())), new e(cardJsonStringArray)), new f(cardJsonStringArray)))), new androidx.navigation.internal.i(cardKeyProvider, brazeManager, cardStorageProvider, cardAnalyticsProvider, cardJsonStringArray, 1)));
    }
}
