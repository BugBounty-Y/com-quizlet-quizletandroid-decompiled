package com.braze.storage;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.braze.AbstractC1484j;
import com.braze.C1481g;
import com.braze.enums.CardKey;
import com.braze.events.FeedUpdatedEvent;
import com.braze.managers.C1500m;
import com.braze.models.cards.Card;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.StringUtils;
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.ConcurrentSkipListSet;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class x implements ICardStorageProvider {
    public final C1500m a;
    public final SharedPreferences b;
    public final AbstractSet c;
    public final AbstractSet d;
    public final com.braze.analytics.b e;

    public x(Context context, String str, C1500m brazeManager) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        this.a = brazeManager;
        this.e = new com.braze.analytics.b();
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.appboy.storage.feedstorageprovider" + StringUtils.getCacheFileSuffix(context, str == null ? "" : str), 0);
        this.b = sharedPreferences;
        this.c = a(w.d);
        this.d = a(w.c);
        SharedPreferences.Editor editorEdit = sharedPreferences.edit();
        editorEdit.putString("uid", str);
        editorEdit.apply();
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Updating offline feed for user with id: ", str);
    }

    @Override // com.braze.storage.ICardStorageProvider
    public final void markCardAsClicked(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
    }

    @Override // com.braze.storage.ICardStorageProvider
    public final void markCardAsDismissed(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
    }

    @Override // com.braze.storage.ICardStorageProvider
    public final void markCardAsViewed(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        if (this.c.contains(cardId)) {
            return;
        }
        this.c.add(cardId);
        a(this.c, w.d);
    }

    @Override // com.braze.storage.ICardStorageProvider
    public final void markCardAsVisuallyRead(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        if (this.d.contains(cardId)) {
            return;
        }
        this.d.add(cardId);
        a(this.d, w.c);
    }

    public final void a(AbstractSet cardIds, w property) {
        Intrinsics.checkNotNullParameter(cardIds, "cardIds");
        Intrinsics.checkNotNullParameter(property, "property");
        String str = property.a;
        SharedPreferences.Editor editorEdit = this.b.edit();
        if (cardIds.isEmpty()) {
            editorEdit.remove(str);
        } else {
            editorEdit.putStringSet(str, cardIds);
        }
        editorEdit.apply();
    }

    public final AbstractSet a(w wVar) {
        String str = wVar.b;
        if (this.b.contains(str)) {
            HashSet hashSet = null;
            String input = this.b.getString(str, null);
            if (input != null) {
                Intrinsics.checkNotNullParameter(input, "input");
                hashSet = new HashSet();
                String[] strArr = (String[]) StringsKt__StringsKt.split$default(input, new String[]{";"}, false, 0, 6, null).toArray(new String[0]);
                Collections.addAll(hashSet, Arrays.copyOf(strArr, strArr.length));
            }
            SharedPreferences.Editor editorEdit = this.b.edit();
            editorEdit.remove(str);
            editorEdit.apply();
            if (hashSet != null) {
                a(hashSet, wVar);
                return hashSet;
            }
        }
        return new ConcurrentSkipListSet(this.b.getStringSet(wVar.a, new HashSet()));
    }

    public final FeedUpdatedEvent a(JSONArray cardsArray, String str) throws JSONException {
        Intrinsics.checkNotNullParameter(cardsArray, "cardsArray");
        String str2 = str == null ? "" : str;
        String string = this.b.getString("uid", "");
        if (Intrinsics.b(string, str2)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new D(str, 14), 6, (Object) null);
            long jNowInSeconds = DateTimeUtils.nowInSeconds();
            SharedPreferences.Editor editorEdit = this.b.edit();
            if (cardsArray.length() == 0) {
                editorEdit.remove("cards");
            } else {
                editorEdit.putString("cards", cardsArray.toString());
            }
            editorEdit.putLong("cards_timestamp", jNowInSeconds);
            editorEdit.apply();
            AbstractSet abstractSet = this.c;
            Intrinsics.checkNotNullParameter(cardsArray, "cardsArray");
            HashSet hashSet = new HashSet();
            int length = cardsArray.length();
            for (int i = 0; i < length; i++) {
                JSONObject jSONObject = cardsArray.getJSONObject(i);
                CardKey cardKey = CardKey.ID;
                if (jSONObject.has(cardKey.getFeedKey())) {
                    String string2 = jSONObject.getString(cardKey.getFeedKey());
                    Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
                    hashSet.add(string2);
                }
            }
            abstractSet.retainAll(hashSet);
            a(this.c, w.d);
            AbstractSet abstractSet2 = this.d;
            Intrinsics.checkNotNullParameter(cardsArray, "cardsArray");
            HashSet hashSet2 = new HashSet();
            int length2 = cardsArray.length();
            for (int i2 = 0; i2 < length2; i2++) {
                JSONObject jSONObject2 = cardsArray.getJSONObject(i2);
                CardKey cardKey2 = CardKey.ID;
                if (jSONObject2.has(cardKey2.getFeedKey())) {
                    String string3 = jSONObject2.getString(cardKey2.getFeedKey());
                    Intrinsics.checkNotNullExpressionValue(string3, "getString(...)");
                    hashSet2.add(string3);
                }
            }
            abstractSet2.retainAll(hashSet2);
            a(this.d, w.c);
            return a(cardsArray, str, false, jNowInSeconds);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1481g(23, str, string), 7, (Object) null);
        return null;
    }

    public static final String a(String str, String str2) {
        return AbstractC0147y.e("The received cards are for user ", str, " and the current user is ", str2, ", the cards will be discarded and no changes will be made.");
    }

    public final FeedUpdatedEvent a(JSONArray jSONArray, String str, boolean z, long j) {
        List listA;
        if (jSONArray.length() == 0) {
            listA = new ArrayList();
        } else {
            listA = com.braze.models.g.a(jSONArray, new CardKey.Provider(false), this.a, this, this.e);
        }
        List<Card> list = listA;
        for (Card card : list) {
            if (this.c.contains(card.getId())) {
                card.setViewed(true);
                card.setIndicatorHighlighted(true);
            }
            if (this.d.contains(card.getId())) {
                card.setIndicatorHighlighted(true);
            }
        }
        return new FeedUpdatedEvent(list, str, z, j);
    }
}
