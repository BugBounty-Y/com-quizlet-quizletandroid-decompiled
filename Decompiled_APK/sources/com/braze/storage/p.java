package com.braze.storage;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.navigation.compose.C1277j;
import com.braze.AbstractC1477c;
import com.braze.AbstractC1484j;
import com.braze.C1480f;
import com.braze.C1481g;
import com.braze.enums.CardKey;
import com.braze.events.ContentCardsUpdatedEvent;
import com.braze.managers.C1500m;
import com.braze.models.cards.Card;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.StringUtils;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.M;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlin.jvm.internal.O;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class p implements ICardStorageProvider {
    public static final Set l;
    public final String a;
    public final C1500m b;
    public long c;
    public long d;
    public final LinkedHashSet e;
    public final LinkedHashSet f;
    public final LinkedHashSet g;
    public final Map h;
    public final SharedPreferences i;
    public final SharedPreferences j;
    public final com.braze.analytics.a k;

    static {
        String[] elements = {CardKey.VIEWED.getContentCardsKey(), CardKey.DISMISSED.getContentCardsKey()};
        Intrinsics.checkNotNullParameter(elements, "elements");
        l = C4933y.T(elements);
    }

    public p(Context context, String userId, String apiKey, C1500m brazeManager, String currentSdkVersion) throws NoSuchAlgorithmException {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(userId, "userId");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        Intrinsics.checkNotNullParameter(currentSdkVersion, "currentSdkVersion");
        this.a = userId;
        this.b = brazeManager;
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        this.e = linkedHashSet;
        LinkedHashSet linkedHashSet2 = new LinkedHashSet();
        this.f = linkedHashSet2;
        LinkedHashSet linkedHashSet3 = new LinkedHashSet();
        this.g = linkedHashSet3;
        this.h = new LinkedHashMap();
        String cacheFileSuffix = StringUtils.getCacheFileSuffix(context, userId, apiKey);
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.appboy.storage.content_cards_storage_provider.cards" + cacheFileSuffix, 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        this.i = sharedPreferences;
        SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.braze.storage.content_cards_storage_provider.metadata" + cacheFileSuffix, 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences2, "getSharedPreferences(...)");
        this.j = sharedPreferences2;
        this.k = new com.braze.analytics.a();
        Map<String, ?> all = sharedPreferences.getAll();
        Intrinsics.e(all, "null cannot be cast to non-null type kotlin.collections.MutableMap<kotlin.String, kotlin.String>");
        this.h = O.c(all);
        Set<String> stringSet = sharedPreferences2.getStringSet("dismissed", new HashSet());
        linkedHashSet.addAll(stringSet != null ? CollectionsKt.J(stringSet) : M.a);
        Set<String> stringSet2 = sharedPreferences2.getStringSet("expired", new HashSet());
        linkedHashSet3.addAll(stringSet2 != null ? CollectionsKt.J(stringSet2) : M.a);
        Set<String> stringSet3 = sharedPreferences2.getStringSet("test", new HashSet());
        linkedHashSet2.addAll(stringSet3 != null ? CollectionsKt.J(stringSet3) : M.a);
        String string = sharedPreferences2.getString("last_accessed_sdk_version", "");
        if (!Intrinsics.b(currentSdkVersion, string)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new C1481g(22, string, currentSdkVersion), 6, (Object) null);
            sharedPreferences2.edit().putLong("last_full_sync_at", 0L).putString("last_accessed_sdk_version", currentSdkVersion).apply();
        }
        this.c = sharedPreferences2.getLong("last_card_updated_at", 0L);
        this.d = sharedPreferences2.getLong("last_full_sync_at", 0L);
    }

    public static final String a(String str, String str2) {
        return AbstractC0147y.e("Detected SDK update from '", str, "' -> '", str2, "'. Clearing config update time.");
    }

    public static final String b(String str) {
        return AbstractC1484j.a("Adding card to test cache: ", str);
    }

    public static final String c(String str) {
        return AbstractC1484j.a("Deleting expired card from storage with id: ", str);
    }

    public static final String d(JSONObject jSONObject) {
        return assistantMode.refactored.a.j("Server card was locally dismissed already. Not adding card to storage. Server card: ", jSONObject);
    }

    public static final String e(String str) {
        return AbstractC1484j.a("Card not present in storage for id: ", str);
    }

    public static final String f(String str) {
        return AbstractC1484j.a("Failed to read card json from storage. Json: ", str);
    }

    public static final String h(String str) {
        return AbstractC1484j.a("Removing card from test cache: ", str);
    }

    public static final String i(String str) {
        return AbstractC1484j.a("Server card is marked as removed. Removing from card storage with id: ", str);
    }

    public static final String j(String str) {
        return AbstractC1484j.a("Server card is marked as dismissed. Adding to dismissed cached and removing from card storage with id: ", str);
    }

    public static final String k(String str) {
        return AbstractC1484j.a("Can't update card field. Json cannot be parsed from disk or is not present. Id: ", str);
    }

    public static final String l(String str) {
        return AbstractC1484j.a("Removing card from storage with id: ", str);
    }

    public static final String m(String str) {
        return AbstractC1484j.a("Writing card to storage with id: ", str);
    }

    public final void g(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new D(cardId, 6), 6, (Object) null);
        LinkedHashSet linkedHashSet = this.f;
        linkedHashSet.remove(cardId);
        kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new i(this, linkedHashSet, null), 3);
    }

    @Override // com.braze.storage.ICardStorageProvider
    public final void markCardAsClicked(String cardId) throws JSONException {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        a(cardId, CardKey.CLICKED);
    }

    @Override // com.braze.storage.ICardStorageProvider
    public final void markCardAsDismissed(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        this.e.add(cardId);
        kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new C1519f(this, null), 3);
        a(cardId, (JSONObject) null);
    }

    @Override // com.braze.storage.ICardStorageProvider
    public final void markCardAsViewed(String cardId) throws JSONException {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        a(cardId, CardKey.VIEWED);
    }

    @Override // com.braze.storage.ICardStorageProvider
    public final void markCardAsVisuallyRead(String cardId) throws JSONException {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        a(cardId, CardKey.READ);
    }

    public static final String b(JSONObject jSONObject) {
        return assistantMode.refactored.a.j("Server card json: ", jSONObject);
    }

    public static final String c(JSONObject jSONObject) {
        return assistantMode.refactored.a.j("Cached card json: ", jSONObject);
    }

    public static final String e(JSONObject jSONObject) {
        return assistantMode.refactored.a.j("Server card has expired already. Not adding card to storage. Server card: ", jSONObject);
    }

    public static final String d() {
        return "Input user id was null. Defaulting to the empty user id";
    }

    public static final String b() {
        return "Clearing content card storage.";
    }

    public static final String c() {
        return "The server card received is older than the cached card. Not updating the cached card.";
    }

    public final JSONObject d(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        String str = (String) this.h.get(cardId);
        if (str == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(cardId, 10), 7, (Object) null);
            return null;
        }
        try {
            return new JSONObject(str);
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new D(str, 11), 4, (Object) null);
            return null;
        }
    }

    public final void a(JSONObject json) throws JSONException {
        JSONObject jSONObject;
        Set setA0 = CollectionsKt.A0(this.e);
        Set setA02 = CollectionsKt.A0(this.g);
        String cardId = json.getString(CardKey.ID.getContentCardsKey());
        Intrinsics.d(cardId);
        JSONObject jSONObjectD = d(cardId);
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.communication.dust.j(json, 8), 7, (Object) null);
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.communication.dust.j(jSONObjectD, 9), 7, (Object) null);
        Intrinsics.checkNotNullParameter(json, "serverCard");
        if (jSONObjectD != null) {
            String contentCardsKey = CardKey.CREATED.getContentCardsKey();
            if (jSONObjectD.has(contentCardsKey) && json.has(contentCardsKey) && jSONObjectD.getLong(contentCardsKey) > json.getLong(contentCardsKey)) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new B(15), 6, (Object) null);
                return;
            }
        }
        CardKey cardKey = CardKey.REMOVED;
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(cardKey, "cardKey");
        String contentCardsKey2 = cardKey.getContentCardsKey();
        if (json.has(contentCardsKey2) ? json.getBoolean(contentCardsKey2) : false) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(cardId, 3), 7, (Object) null);
            Intrinsics.checkNotNullParameter(cardId, "cardId");
            this.e.remove(cardId);
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new h(this, null), 3);
            g(cardId);
            a(cardId, (JSONObject) null);
            return;
        }
        if (setA0.contains(cardId)) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.communication.dust.j(json, 10), 7, (Object) null);
            return;
        }
        if (setA02.contains(cardId)) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.communication.dust.j(json, 11), 7, (Object) null);
            return;
        }
        CardKey cardKey2 = CardKey.DISMISSED;
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(cardKey2, "cardKey");
        String contentCardsKey3 = cardKey2.getContentCardsKey();
        if (json.has(contentCardsKey3) ? json.getBoolean(contentCardsKey3) : false) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(cardId, 4), 7, (Object) null);
            Intrinsics.checkNotNullParameter(cardId, "cardId");
            this.e.add(cardId);
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new C1519f(this, null), 3);
            a(cardId, (JSONObject) null);
            return;
        }
        Intrinsics.checkNotNullParameter(json, "serverCard");
        if (jSONObjectD == null) {
            jSONObject = json;
        } else {
            jSONObject = new JSONObject();
            Iterator<String> itKeys = jSONObjectD.keys();
            while (itKeys.hasNext()) {
                String next = itKeys.next();
                jSONObject.put(next, jSONObjectD.get(next));
            }
            Iterator<String> itKeys2 = json.keys();
            while (itKeys2.hasNext()) {
                String next2 = itKeys2.next();
                if (l.contains(next2)) {
                    jSONObject.put(next2, jSONObjectD.getBoolean(next2) || json.getBoolean(next2));
                } else {
                    jSONObject.put(next2, json.get(next2));
                }
            }
        }
        a(cardId, jSONObject);
        CardKey cardKey3 = CardKey.IS_TEST;
        Intrinsics.checkNotNullParameter(json, "json");
        Intrinsics.checkNotNullParameter(cardKey3, "cardKey");
        String contentCardsKey4 = cardKey3.getContentCardsKey();
        if (json.has(contentCardsKey4) ? json.getBoolean(contentCardsKey4) : false) {
            a(cardId);
        }
    }

    public final ContentCardsUpdatedEvent a(com.braze.models.response.c contentCardsResponse, String str) {
        Intrinsics.checkNotNullParameter(contentCardsResponse, "contentCardsResponse");
        J j = new J();
        j.a = str;
        if (str == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new B(14), 7, (Object) null);
            j.a = "";
        }
        if (!Intrinsics.b(this.a, j.a)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new C1277j(19, j, this), 6, (Object) null);
            return null;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new C1480f(j, 7), 6, (Object) null);
        Intrinsics.checkNotNullParameter(contentCardsResponse, "contentCardsResponse");
        SharedPreferences.Editor editorEdit = this.j.edit();
        long j2 = contentCardsResponse.a;
        if (j2 != -1) {
            this.c = j2;
            editorEdit.putLong("last_card_updated_at", j2);
        }
        long j3 = contentCardsResponse.b;
        if (j3 != -1) {
            this.d = j3;
            editorEdit.putLong("last_full_sync_at", j3);
        }
        editorEdit.apply();
        this.j.edit().putLong("last_storage_update_timestamp", DateTimeUtils.nowInSeconds()).apply();
        LinkedHashSet cardIdsToRetain = new LinkedHashSet();
        JSONArray jSONArray = contentCardsResponse.d;
        if (jSONArray != null && jSONArray.length() != 0) {
            kotlin.sequences.t tVarH = kotlin.sequences.q.h(kotlin.sequences.q.e(CollectionsKt.D(kotlin.ranges.l.h(0, jSONArray.length())), new m(jSONArray)), new n(jSONArray));
            Iterator it2 = tVarH.b.iterator();
            while (it2.hasNext()) {
                JSONObject jSONObject = (JSONObject) tVarH.c.invoke(it2.next());
                a(jSONObject);
                String string = jSONObject.getString(CardKey.ID.getContentCardsKey());
                Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                cardIdsToRetain.add(string);
            }
        }
        if (contentCardsResponse.c) {
            Intrinsics.checkNotNullParameter(cardIdsToRetain, "cardIdsToRetain");
            this.e.retainAll(cardIdsToRetain);
            com.braze.coroutine.f fVar = com.braze.coroutine.f.a;
            kotlinx.coroutines.E.A(fVar, null, null, new k(this, null), 3);
            Intrinsics.checkNotNullParameter(cardIdsToRetain, "cardIdsToRetain");
            LinkedHashSet linkedHashSet = this.g;
            linkedHashSet.retainAll(cardIdsToRetain);
            kotlinx.coroutines.E.A(fVar, null, null, new l(this, linkedHashSet, null), 3);
            cardIdsToRetain.addAll(this.f);
            a(cardIdsToRetain);
        }
        return a(false);
    }

    public static final String a(J j, p pVar) {
        StringBuilder sb = new StringBuilder("The received cards are for user ");
        sb.append((String) j.a);
        sb.append(" and the current user is ");
        return AbstractC1477c.a(sb, pVar.a, " , the cards will be discarded and no changes will be made.");
    }

    public static final String a(J j) {
        return "Updating offline Content Cards for user with id: " + ((String) j.a);
    }

    public final ContentCardsUpdatedEvent a(boolean z) {
        CardKey.Provider provider = CardKey.Provider.CONTENT_CARDS;
        JSONArray jSONArray = new JSONArray();
        Iterator it2 = this.h.values().iterator();
        while (it2.hasNext()) {
            jSONArray.put((String) it2.next());
        }
        List listA = com.braze.models.g.a(jSONArray, provider, this.b, this, this.k);
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        for (Object obj : listA) {
            if (((Card) obj).isExpired()) {
                arrayList.add(obj);
            } else {
                arrayList2.add(obj);
            }
        }
        ArrayList arrayList3 = arrayList2;
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            a((Card) it3.next());
        }
        return new ContentCardsUpdatedEvent(arrayList3, this.a, this.j.getLong("last_storage_update_timestamp", 0L), z);
    }

    public final void a(Card card) {
        Intrinsics.checkNotNullParameter(card, "card");
        String cardId = card.getId();
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(cardId, 2), 7, (Object) null);
        a(cardId, (JSONObject) null);
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        this.g.add(cardId);
        kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new g(this, null), 3);
        g(cardId);
    }

    public final void a(String cardId, CardKey cardKey) throws JSONException {
        Boolean value = Boolean.TRUE;
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        Intrinsics.checkNotNullParameter(cardKey, "cardKey");
        Intrinsics.checkNotNullParameter(value, "value");
        JSONObject jSONObjectD = d(cardId);
        if (jSONObjectD == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(cardId, 9), 7, (Object) null);
            return;
        }
        try {
            jSONObjectD.put(cardKey.getContentCardsKey(), value);
            a(cardId, jSONObjectD);
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.requests.framework.o(cardKey, 6), 4, (Object) null);
        }
    }

    public static final String a(Object obj, CardKey cardKey) {
        return "Failed to update card json field to " + obj + " with key: " + cardKey;
    }

    public final void a(String cardId, JSONObject jSONObject) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        if (jSONObject == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(cardId, 7), 7, (Object) null);
            this.h.remove(cardId);
        } else {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(cardId, 8), 7, (Object) null);
            this.h.put(cardId, jSONObject.toString());
        }
        kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new o(this, jSONObject, cardId, null), 3);
    }

    public final void a(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new D(cardId, 5), 6, (Object) null);
        LinkedHashSet linkedHashSet = this.f;
        linkedHashSet.add(cardId);
        this.j.edit().putStringSet("test", linkedHashSet).apply();
    }

    public final void a(LinkedHashSet cardIdsToRetain) {
        Intrinsics.checkNotNullParameter(cardIdsToRetain, "cardIdsToRetain");
        Set setKeySet = this.h.keySet();
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1277j(20, cardIdsToRetain, setKeySet), 7, (Object) null);
        ArrayList arrayList = new ArrayList();
        for (Object obj : setKeySet) {
            if (!cardIdsToRetain.contains((String) obj)) {
                arrayList.add(obj);
            }
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            this.h.remove((String) it2.next());
        }
        kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new j(this, arrayList, null), 3);
    }

    public static final String a(Set set, Set set2) {
        return "Retaining card ids: " + set + " among cached card ids: " + set2;
    }

    public final void a() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new B(16), 7, (Object) null);
        this.h.clear();
        this.i.edit().clear().apply();
        this.j.edit().clear().apply();
    }
}
