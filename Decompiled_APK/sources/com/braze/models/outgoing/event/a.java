package com.braze.models.outgoing.event;

import androidx.lifecycle.C1247h;
import androidx.navigation.compose.C1277j;
import com.braze.C1479e;
import com.braze.C1481g;
import com.braze.P;
import com.braze.S;
import com.braze.V;
import com.braze.dispatch.j;
import com.braze.enums.d;
import com.braze.enums.e;
import com.braze.enums.h;
import com.braze.managers.C;
import com.braze.models.IBrazeLocation;
import com.braze.models.i;
import com.braze.models.o;
import com.braze.models.outgoing.BrazeProperties;
import com.braze.r;
import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.UUID;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.I;
import kotlin.text.x;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class a {
    public static final i b(String str, BrazeProperties brazeProperties) throws JSONException {
        JSONObject jSONObjectPut = new JSONObject().put("n", str);
        if (brazeProperties != null && brazeProperties.getSize() > 0) {
            jSONObjectPut.put("p", brazeProperties.forJsonPut());
        }
        e eVar = e.e;
        Intrinsics.d(jSONObjectPut);
        return new b(eVar, jSONObjectPut, 0.0d, 12);
    }

    public static final i d(String str) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        JSONArray jSONArray = new JSONArray();
        jSONArray.put(str);
        jSONObject.put("ids", jSONArray);
        return new b(e.o, jSONObject, 0.0d, 12);
    }

    public static final i f(String str) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        JSONArray jSONArray = new JSONArray();
        jSONArray.put(str);
        jSONObject.put("ids", jSONArray);
        return new b(e.q, jSONObject, 0.0d, 12);
    }

    public static final i h(String str) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        JSONArray jSONArray = new JSONArray();
        jSONArray.put(str);
        jSONObject.put("ids", jSONArray);
        return new b(e.r, jSONObject, 0.0d, 12);
    }

    public static final i j(String str) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        JSONArray jSONArray = new JSONArray();
        jSONArray.put(str);
        jSONObject.put("ids", jSONArray);
        return new b(e.p, jSONObject, 0.0d, 12);
    }

    public static final i l(String str) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        JSONArray jSONArray = new JSONArray();
        jSONArray.put(str);
        jSONObject.put("ids", jSONArray);
        return new b(e.m, jSONObject, 0.0d, 12);
    }

    public static final i n(String str) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        JSONArray jSONArray = new JSONArray();
        jSONArray.put(str);
        jSONObject.put("ids", jSONArray);
        return new b(e.l, jSONObject, 0.0d, 12);
    }

    public static final i p(String str) {
        return new b(e.y, b.g.a(str, (String) null, (String) null), 0.0d, 12);
    }

    public static final i q(String str) throws JSONException {
        JSONObject jSONObjectPut = new JSONObject().put("n", str);
        e eVar = e.j;
        Intrinsics.d(jSONObjectPut);
        return new b(eVar, jSONObjectPut, 0.0d, 12);
    }

    public static final i r(String str, String str2) throws JSONException {
        JSONObject jSONObjectPut = new JSONObject().put("key", str).put("value", str2);
        e eVar = e.u;
        Intrinsics.d(jSONObjectPut);
        return new b(eVar, jSONObjectPut, 0.0d, 12);
    }

    public static final i t(String str, String str2) throws JSONException {
        JSONObject jSONObjectPut = new JSONObject().put("a", str).put("l", str2);
        e eVar = e.A;
        Intrinsics.d(jSONObjectPut);
        return new b(eVar, jSONObjectPut, 0.0d, 12);
    }

    public final i a(String eventName, BrazeProperties brazeProperties) {
        Intrinsics.checkNotNullParameter(eventName, "eventName");
        return a(new C1479e(eventName, brazeProperties, 2));
    }

    public final i c(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        return a(new C(cardId, 18));
    }

    public final i e(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        return a(new C(cardId, 20));
    }

    public final i g(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        return a(new C(cardId, 21));
    }

    public final i i(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        return a(new C(cardId, 23));
    }

    public final i k(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        return a(new C(cardId, 19));
    }

    public final i m(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        return a(new C(cardId, 17));
    }

    public final i o(String triggerId) {
        Intrinsics.checkNotNullParameter(triggerId, "triggerId");
        return a(new C(triggerId, 22));
    }

    public final i s(String alias, String label) {
        Intrinsics.checkNotNullParameter(alias, "alias");
        Intrinsics.checkNotNullParameter(label, "label");
        return a(new C1481g(12, alias, label));
    }

    public static final String c() {
        return "Failed to create event";
    }

    public final i a(final String productId, final String currencyCode, final BigDecimal price, final int i, final BrazeProperties brazeProperties) {
        Intrinsics.checkNotNullParameter(productId, "productId");
        Intrinsics.checkNotNullParameter(currencyCode, "currencyCode");
        Intrinsics.checkNotNullParameter(price, "price");
        return a(new Function0() { // from class: com.braze.models.outgoing.event.c
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                return a.a(brazeProperties, productId, currencyCode, price, i);
            }
        });
    }

    public final i e(String serializedEvent, String uniqueIdentifier) {
        Intrinsics.checkNotNullParameter(serializedEvent, "serializedEvent");
        Intrinsics.checkNotNullParameter(uniqueIdentifier, "uniqueIdentifier");
        return a(new C1481g(17, serializedEvent, uniqueIdentifier));
    }

    public final i i(String triggerId, String buttonId) {
        Intrinsics.checkNotNullParameter(triggerId, "triggerId");
        Intrinsics.checkNotNullParameter(buttonId, "buttonId");
        return a(new C1481g(14, triggerId, buttonId));
    }

    public final i k(String triggerId, String str) {
        Intrinsics.checkNotNullParameter(triggerId, "triggerId");
        return a(new C1481g(15, triggerId, str));
    }

    public final i m(String triggerId, String str) {
        Intrinsics.checkNotNullParameter(triggerId, "triggerId");
        return a(new C1481g(13, triggerId, str));
    }

    public final i o(String campaignId, String pageId) {
        Intrinsics.checkNotNullParameter(campaignId, "campaignId");
        Intrinsics.checkNotNullParameter(pageId, "pageId");
        return a(new C1481g(18, campaignId, pageId));
    }

    public static final i a(BrazeProperties brazeProperties, String str, String str2, BigDecimal bigDecimal, int i) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("pid", str);
        jSONObject.put("c", str2);
        Intrinsics.checkNotNullParameter(bigDecimal, "<this>");
        BigDecimal scale = bigDecimal.setScale(2, RoundingMode.HALF_UP);
        Intrinsics.checkNotNullExpressionValue(scale, "setScale(...)");
        jSONObject.put("p", scale.doubleValue());
        jSONObject.put("q", i);
        if (brazeProperties != null && brazeProperties.getSize() > 0) {
            jSONObject.put("pr", brazeProperties.forJsonPut());
        }
        return new b(e.f, jSONObject, 0.0d, 12);
    }

    public static final i p(String str, String str2) throws JSONException {
        JSONObject jSONObjectPut = new JSONObject().put("cid", str).put("a", str2);
        e eVar = e.g;
        Intrinsics.d(jSONObjectPut);
        return new b(eVar, jSONObjectPut, 0.0d, 12);
    }

    public final i q(String key, String value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        return a(new C1481g(11, key, value));
    }

    public static final i b(IBrazeLocation iBrazeLocation) {
        return new b(e.d, iBrazeLocation.forJsonPut(), 0.0d, 12);
    }

    public static final i f(String str, String uniqueIdentifier) throws JSONException {
        o oVar;
        JSONObject jSONObject = new JSONObject(str);
        String value = jSONObject.getString("name");
        d dVar = e.b;
        Intrinsics.d(value);
        dVar.getClass();
        Intrinsics.checkNotNullParameter(value, "value");
        Object obj = e.c.get(value);
        if (obj == null) {
            obj = e.L;
        }
        e eventType = (e) obj;
        JSONObject eventData = jSONObject.getJSONObject("data");
        double d = jSONObject.getDouble("time");
        String optionalString = JsonUtils.getOptionalString(jSONObject, "user_id");
        String sessionId = JsonUtils.getOptionalString(jSONObject, "session_id");
        Intrinsics.d(eventData);
        Intrinsics.checkNotNullParameter(eventType, "eventType");
        Intrinsics.checkNotNullParameter(eventData, "eventData");
        Intrinsics.checkNotNullParameter(uniqueIdentifier, "uniqueIdentifier");
        b bVar = new b(eventType, eventData, d, uniqueIdentifier);
        bVar.e.setValue(bVar, b.h[0], optionalString);
        if (sessionId != null) {
            Intrinsics.checkNotNullParameter(sessionId, "sessionId");
            UUID uuidFromString = UUID.fromString(sessionId);
            Intrinsics.checkNotNullExpressionValue(uuidFromString, "fromString(...)");
            oVar = new o(uuidFromString);
        } else {
            oVar = null;
        }
        bVar.a(oVar);
        return bVar;
    }

    public static final i j(String str, String str2) {
        return new b(e.z, b.g.a(str, str2, (String) null), 0.0d, 12);
    }

    public static final i l(String str, String str2) {
        return new b(e.x, b.g.a(str, (String) null, str2), 0.0d, 12);
    }

    public static final i n(String str, String str2) {
        return new b(e.w, b.g.a(str, (String) null, str2), 0.0d, 12);
    }

    public static final i b(Throwable throwable, o oVar, boolean z) throws JSONException {
        String str;
        StringBuilder sb = new StringBuilder("\n                original_sdk_version: 36.0.0\n                exception_class: ");
        sb.append(throwable.getClass().getName());
        sb.append("\n                available_cpus: ");
        sb.append(Runtime.getRuntime().availableProcessors());
        sb.append("\n                ");
        if (oVar != null) {
            str = "session_id: " + oVar;
        } else {
            str = null;
        }
        sb.append(str);
        sb.append("\n                ");
        b.g.getClass();
        Intrinsics.checkNotNullParameter(throwable, "throwable");
        StringWriter stringWriter = new StringWriter();
        throwable.printStackTrace(new PrintWriter(stringWriter));
        String string = stringWriter.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        sb.append(I.C(5000, string));
        sb.append("\n            ");
        JSONObject jSONObjectPut = new JSONObject().put("e", x.c(sb.toString()));
        if (!z) {
            jSONObjectPut.put("nop", true);
        }
        e eVar = e.k;
        Intrinsics.d(jSONObjectPut);
        return new b(eVar, jSONObjectPut, 0.0d, 12);
    }

    public final i a(IBrazeLocation location) {
        Intrinsics.checkNotNullParameter(location, "location");
        return a(new com.braze.models.outgoing.a(5));
    }

    public final i a(Throwable throwable, o oVar, boolean z) {
        Intrinsics.checkNotNullParameter(throwable, "throwable");
        return a(new r(throwable, oVar, z, 2));
    }

    public final i a() {
        Intrinsics.checkNotNullParameter("feed_displayed", "name");
        return a(new com.braze.models.outgoing.a(3));
    }

    public final i a(String customUserAttributeKey, int i) {
        Intrinsics.checkNotNullParameter(customUserAttributeKey, "customUserAttributeKey");
        return a(new P(customUserAttributeKey, i, 1));
    }

    public final i a(String key, String value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        return a(new C1481g(16, key, value));
    }

    public final i a(String key, String[] strArr) {
        Intrinsics.checkNotNullParameter(key, "key");
        return a(new C1277j(13, key, strArr));
    }

    public final i a(o sessionId) {
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        return a(new C1247h(sessionId, 27));
    }

    public final i a(long j) {
        return a(new j(8, j));
    }

    public final i a(String key, double d, double d2) {
        Intrinsics.checkNotNullParameter(key, "key");
        return a(new S(key, d, d2, 1));
    }

    public final i a(String key, JSONObject json) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(json, "json");
        return a(new V(1, key, json));
    }

    public final i a(String subscriptionGroupId, h subscriptionGroupStatus) {
        Intrinsics.checkNotNullParameter(subscriptionGroupId, "subscriptionGroupId");
        Intrinsics.checkNotNullParameter(subscriptionGroupStatus, "subscriptionGroupStatus");
        return a(new C1277j(12, subscriptionGroupId, subscriptionGroupStatus));
    }

    public final JSONObject a(String str, String str2, String str3) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        if (str != null && str.length() != 0) {
            JSONArray jSONArray = new JSONArray();
            jSONArray.put(str);
            jSONObject.put("trigger_ids", jSONArray);
        }
        if (str2 != null && str2.length() != 0) {
            jSONObject.put("bid", str2);
        }
        if (str3 != null) {
            jSONObject.put("message_extras", str3);
            return jSONObject;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.models.outgoing.a(6), 6, (Object) null);
        return jSONObject;
    }

    public static final i b(String str, int i) throws JSONException {
        JSONObject jSONObjectPut = new JSONObject().put("key", str).put("value", i);
        e eVar = e.s;
        Intrinsics.d(jSONObjectPut);
        return new b(eVar, jSONObjectPut, 0.0d, 12);
    }

    public final i a(Function0 function0) {
        try {
            return (i) function0.invoke();
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.models.outgoing.a(4), 4, (Object) null);
            return null;
        }
    }

    public static final i b(String str, String str2) throws JSONException {
        JSONObject jSONObjectPut = new JSONObject().put("key", str).put("value", str2);
        e eVar = e.t;
        Intrinsics.d(jSONObjectPut);
        return new b(eVar, jSONObjectPut, 0.0d, 12);
    }

    public static final i b(String str, String[] strArr) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("key", str);
        if (strArr == null) {
            jSONObject.put("value", JSONObject.NULL);
        } else {
            jSONObject.put("value", JsonUtils.constructJsonArray(strArr));
        }
        return new b(e.v, jSONObject, 0.0d, 12);
    }

    public static final i b(o oVar) {
        b bVar = new b(e.B, (JSONObject) null, 0.0d, 14);
        bVar.a(oVar);
        return bVar;
    }

    public static final i b(long j) throws JSONException {
        JSONObject jSONObjectPut = new JSONObject().put("d", j);
        e eVar = e.C;
        Intrinsics.d(jSONObjectPut);
        return new b(eVar, jSONObjectPut, 0.0d, 12);
    }

    public static final i b(String str, double d, double d2) throws JSONException {
        JSONObject jSONObjectPut = new JSONObject().put("key", str).put("latitude", d).put("longitude", d2);
        e eVar = e.D;
        Intrinsics.d(jSONObjectPut);
        return new b(eVar, jSONObjectPut, 0.0d, 12);
    }

    public static final i b(String str, JSONObject jSONObject) throws JSONException {
        JSONObject jSONObjectPut = new JSONObject().put("key", str).put("value", jSONObject);
        e eVar = e.F;
        Intrinsics.d(jSONObjectPut);
        return new b(eVar, jSONObjectPut, 0.0d, 12);
    }

    public static final i b(String str, h hVar) throws JSONException {
        String str2;
        JSONObject jSONObjectPut = new JSONObject().put("group_id", str);
        int iOrdinal = hVar.ordinal();
        if (iOrdinal == 0) {
            str2 = "subscribed";
        } else if (iOrdinal == 1) {
            str2 = "unsubscribed";
        } else {
            throw new NoWhenBranchMatchedException();
        }
        JSONObject jSONObjectPut2 = jSONObjectPut.put("status", str2);
        e eVar = e.G;
        Intrinsics.d(jSONObjectPut2);
        return new b(eVar, jSONObjectPut2, 0.0d, 12);
    }

    public static final String b() {
        return "Message extras are null, not adding to event";
    }
}
