package com.braze.models.response;

import androidx.compose.animation.d0;
import androidx.core.view.C;
import com.braze.managers.o0;
import com.braze.managers.s0;
import com.braze.storage.e0;
import com.braze.support.BrazeLogger;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import kotlin.collections.CollectionsKt;
import kotlin.collections.J;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.q;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class m {
    public Long A;
    public long B;
    public long C;
    public long D;
    public Map E;
    public boolean F;
    public int G;
    public long a;
    public Set b;
    public Set c;
    public Set d;
    public int e;
    public int f;
    public int g;
    public boolean h;
    public boolean i;
    public boolean j;
    public long k;
    public boolean l;
    public boolean m;
    public int n;
    public boolean o;
    public long p;
    public boolean q;
    public int r;
    public int s;
    public boolean t;
    public long u;
    public int v;
    public int w;
    public int x;
    public boolean y;
    public String z;

    public m() {
        int i = e0.f;
        int i2 = e0.g;
        this.a = 0L;
        this.b = null;
        this.c = null;
        this.d = null;
        this.e = -1;
        this.f = -1;
        this.g = -1;
        this.h = false;
        this.i = false;
        this.j = false;
        this.k = -1L;
        this.l = false;
        this.m = false;
        this.n = -1;
        this.o = false;
        this.p = 86400L;
        this.q = true;
        this.r = 30;
        this.s = 30;
        this.t = false;
        this.u = -1L;
        this.v = i;
        this.w = i2;
        this.x = 3;
        this.y = false;
        this.z = null;
        this.A = null;
        this.B = 0L;
        this.C = 0L;
        this.D = 0L;
        this.E = null;
        this.F = false;
        this.G = 0;
    }

    public static final String g() {
        return "Caught error parsing global rate limit config.";
    }

    public static final String k(JSONObject jSONObject) {
        return assistantMode.refactored.a.j("sdkDebuggerObject contains invalid values. Disabling SDK debugging. ", jSONObject);
    }

    public final void a(JSONObject jSONObject) throws JSONException {
        int i;
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("banners");
        if (jSONObjectOptJSONObject != null) {
            try {
                this.F = jSONObjectOptJSONObject.getBoolean("enabled");
                i = jSONObjectOptJSONObject.getInt("max_placements");
                this.G = i;
            } catch (JSONException e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.models.outgoing.a(18), 4, (Object) null);
            }
            if (!this.F || i > 0) {
                return;
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new p(this, 0), 7, (Object) null);
            this.F = false;
            this.G = 0;
        }
    }

    public final void b(JSONObject jSONObject) throws JSONException {
        m mVar;
        boolean z;
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("content_cards");
        if (jSONObjectOptJSONObject != null) {
            try {
                z = jSONObjectOptJSONObject.getBoolean("enabled");
                mVar = this;
            } catch (JSONException e) {
                mVar = this;
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) mVar, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.models.outgoing.a(16), 4, (Object) null);
                z = false;
            }
            mVar.j = z;
        }
    }

    public final void c(JSONObject jSONObject) throws JSONException {
        m mVar;
        boolean z;
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("dust");
        if (jSONObjectOptJSONObject != null) {
            try {
                z = jSONObjectOptJSONObject.getBoolean("enabled");
                mVar = this;
            } catch (JSONException e) {
                mVar = this;
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) mVar, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.models.outgoing.a(17), 4, (Object) null);
                z = false;
            }
            mVar.t = z;
        }
    }

    public final void d(JSONObject jSONObject) throws JSONException {
        m mVar;
        boolean z;
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("ephemeral_events");
        if (jSONObjectOptJSONObject != null) {
            try {
                z = jSONObjectOptJSONObject.getBoolean("enabled");
                mVar = this;
            } catch (JSONException e) {
                mVar = this;
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) mVar, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.models.outgoing.a(11), 4, (Object) null);
                z = false;
            }
            mVar.l = z;
        }
    }

    public final void e(JSONObject jSONObject) {
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("feature_flags");
        if (jSONObjectOptJSONObject != null) {
            try {
                this.m = jSONObjectOptJSONObject.optBoolean("enabled");
                this.n = jSONObjectOptJSONObject.getInt("refresh_rate_limit");
            } catch (JSONException e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.models.outgoing.a(15), 4, (Object) null);
                this.m = false;
            }
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return this.a == mVar.a && Intrinsics.b(this.b, mVar.b) && Intrinsics.b(this.c, mVar.c) && Intrinsics.b(this.d, mVar.d) && this.e == mVar.e && this.f == mVar.f && this.g == mVar.g && this.h == mVar.h && this.i == mVar.i && this.j == mVar.j && this.k == mVar.k && this.l == mVar.l && this.m == mVar.m && this.n == mVar.n && this.o == mVar.o && this.p == mVar.p && this.q == mVar.q && this.r == mVar.r && this.s == mVar.s && this.t == mVar.t && this.u == mVar.u && this.v == mVar.v && this.w == mVar.w && this.x == mVar.x && this.y == mVar.y && Intrinsics.b(this.z, mVar.z) && Intrinsics.b(this.A, mVar.A) && this.B == mVar.B && this.C == mVar.C && this.D == mVar.D && Intrinsics.b(this.E, mVar.E) && this.F == mVar.F && this.G == mVar.G;
    }

    public final void f(JSONObject jSONObject) {
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("geofences");
        if (jSONObjectOptJSONObject != null) {
            try {
                this.e = jSONObjectOptJSONObject.getInt("min_time_since_last_request");
                this.f = jSONObjectOptJSONObject.getInt("min_time_since_last_report");
                this.i = jSONObjectOptJSONObject.getBoolean("enabled");
                this.h = true;
                this.g = jSONObjectOptJSONObject.optInt("max_num_to_register", 20);
            } catch (JSONException e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.models.outgoing.a(14), 4, (Object) null);
                this.e = -1;
                this.f = -1;
                this.g = -1;
                this.i = false;
                this.h = false;
            }
        }
    }

    public final void h(JSONObject jSONObject) throws JSONException {
        try {
            JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("global_request_rate_limit");
            if (jSONObjectOptJSONObject != null) {
                if (!jSONObjectOptJSONObject.getBoolean("enabled")) {
                    this.q = false;
                    return;
                }
                int i = jSONObjectOptJSONObject.getInt("refill_rate");
                int i2 = jSONObjectOptJSONObject.getInt("capacity");
                if (i2 < 10) {
                    this.q = false;
                } else if (i > 0) {
                    this.q = true;
                    this.s = i2;
                    this.r = i;
                    g(jSONObjectOptJSONObject);
                }
            }
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.models.outgoing.a(19), 4, (Object) null);
            this.q = false;
            this.E = null;
        }
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        Set set = this.b;
        int iHashCode2 = (iHashCode + (set == null ? 0 : set.hashCode())) * 31;
        Set set2 = this.c;
        int iHashCode3 = (iHashCode2 + (set2 == null ? 0 : set2.hashCode())) * 31;
        Set set3 = this.d;
        int iG = d0.g(d0.b(this.x, d0.b(this.w, d0.b(this.v, d0.d(d0.g(d0.b(this.s, d0.b(this.r, d0.g(d0.d(d0.g(d0.b(this.n, d0.g(d0.g(d0.d(d0.g(d0.g(d0.g(d0.b(this.g, d0.b(this.f, d0.b(this.e, (iHashCode3 + (set3 == null ? 0 : set3.hashCode())) * 31, 31), 31), 31), 31, this.h), 31, this.i), 31, this.j), 31, this.k), 31, this.l), 31, this.m), 31), 31, this.o), 31, this.p), 31, this.q), 31), 31), 31, this.t), 31, this.u), 31), 31), 31), 31, this.y);
        String str = this.z;
        int iHashCode4 = (iG + (str == null ? 0 : str.hashCode())) * 31;
        Long l = this.A;
        int iD = d0.d(d0.d(d0.d((iHashCode4 + (l == null ? 0 : l.hashCode())) * 31, 31, this.B), 31, this.C), 31, this.D);
        Map map = this.E;
        return Integer.hashCode(this.G) + d0.g((iD + (map != null ? map.hashCode() : 0)) * 31, 31, this.F);
    }

    public final void i(JSONObject jSONObject) {
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("push_max");
        if (jSONObjectOptJSONObject != null) {
            try {
                this.o = jSONObjectOptJSONObject.optBoolean("enabled");
                this.p = jSONObjectOptJSONObject.optLong("redeliver_buffer", 86400L);
                this.u = jSONObjectOptJSONObject.optLong("redeliver_dedupe_buffer", -1L);
            } catch (JSONException e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.models.outgoing.a(13), 4, (Object) null);
                this.o = false;
                this.p = 0L;
                this.u = -1L;
            }
        }
    }

    public final void j(JSONObject jSONObject) {
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("sdk_debugger");
        if (jSONObjectOptJSONObject == null) {
            return;
        }
        try {
            o0 o0VarA = s0.k.a(jSONObjectOptJSONObject, false);
            if (o0VarA.a) {
                this.y = true;
                this.z = o0VarA.c;
                Long l = o0VarA.b;
                if (l != null) {
                    this.A = Long.valueOf(l.longValue());
                }
                this.B = o0VarA.d;
                this.C = o0VarA.e;
                this.D = o0VarA.f;
            }
            String str = this.z;
            if (str != null && !StringsKt.O(str) && this.B > 0 && this.C > 0 && this.D > 0) {
                return;
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.communication.dust.j(jSONObjectOptJSONObject, 7), 7, (Object) null);
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.models.outgoing.a(12), 4, (Object) null);
        }
        this.y = false;
        this.z = null;
        this.B = 0L;
        this.C = 0L;
        this.D = 0L;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ServerConfig(configTime=");
        sb.append(this.a);
        sb.append(", blocklistedEvents=");
        sb.append(this.b);
        sb.append(", blocklistedAttributes=");
        sb.append(this.c);
        sb.append(", blocklistedPurchases=");
        sb.append(this.d);
        sb.append(", minTimeSinceLastRequest=");
        sb.append(this.e);
        sb.append(", minTimeSinceLastReport=");
        sb.append(this.f);
        sb.append(", maxNumToRegister=");
        sb.append(this.g);
        sb.append(", geofencesEnabledSet=");
        sb.append(this.h);
        sb.append(", geofencesEnabled=");
        sb.append(this.i);
        sb.append(", isContentCardsFeatureEnabled=");
        sb.append(this.j);
        sb.append(", messagingSessionTimeout=");
        sb.append(this.k);
        sb.append(", ephemeralEventsEnabled=");
        sb.append(this.l);
        sb.append(", featureFlagsEnabled=");
        sb.append(this.m);
        sb.append(", featureFlagsRefreshRateLimit=");
        sb.append(this.n);
        sb.append(", pushMaxEnabled=");
        sb.append(this.o);
        sb.append(", pushMaxRedeliverBuffer=");
        sb.append(this.p);
        sb.append(", globalRequestRateLimitEnabled=");
        sb.append(this.q);
        sb.append(", globalRequestRateLimitBucketRefillRate=");
        sb.append(this.r);
        sb.append(", globalRequestRateLimitBucketCapacity=");
        sb.append(this.s);
        sb.append(", isDustFeatureEnabled=");
        sb.append(this.t);
        sb.append(", pushMaxRedeliverDedupeBuffer=");
        sb.append(this.u);
        sb.append(", defaultBackoffMinSleepMs=");
        sb.append(this.v);
        sb.append(", defaultBackoffMaxSleepMs=");
        sb.append(this.w);
        sb.append(", defaultBackoffScaleFactor=");
        sb.append(this.x);
        sb.append(", sdkDebuggerEnabled=");
        sb.append(this.y);
        sb.append(", sdkDebuggerAuthCode=");
        sb.append(this.z);
        sb.append(", sdkDebuggerExpirationTime=");
        sb.append(this.A);
        sb.append(", sdkDebuggerFlushIntervalBytes=");
        sb.append(this.B);
        sb.append(", sdkDebuggerFlushIntervalSeconds=");
        sb.append(this.C);
        sb.append(", sdkDebuggerMaxPayloadBytes=");
        sb.append(this.D);
        sb.append(", globalRequestRateLimitOverrides=");
        sb.append(this.E);
        sb.append(", bannersEnabled=");
        sb.append(this.F);
        sb.append(", maxBannerPlacements=");
        return android.support.v4.media.session.a.q(sb, this.G, ')');
    }

    public final void g(JSONObject jSONObject) throws JSONException {
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("endpoint_overrides");
        if (jSONObjectOptJSONObject != null) {
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            Iterator<String> itKeys = jSONObjectOptJSONObject.keys();
            Intrinsics.checkNotNullExpressionValue(itKeys, "keys(...)");
            while (itKeys.hasNext()) {
                String destinationSuffix = itKeys.next();
                com.braze.requests.l lVar = com.braze.requests.m.b;
                Intrinsics.d(destinationSuffix);
                lVar.getClass();
                Intrinsics.checkNotNullParameter(destinationSuffix, "destinationSuffix");
                com.braze.requests.m mVar = (com.braze.requests.m) com.braze.requests.m.c.get(destinationSuffix);
                if (mVar != null) {
                    JSONObject jSONObject2 = jSONObjectOptJSONObject.getJSONObject(destinationSuffix);
                    int i = jSONObject2.getInt("capacity");
                    int i2 = jSONObject2.getInt("refill_rate");
                    if (i > 0 && i2 > 0) {
                        linkedHashMap.put(mVar, new j(i, i2));
                    }
                }
            }
            if (linkedHashMap.isEmpty()) {
                return;
            }
            this.E = linkedHashMap;
        }
    }

    public static final String b() {
        return "Error getting required content cards fields. Using defaults.";
    }

    public static final String c() {
        return "Error getting required DUST enabled field. Using default of false.";
    }

    public static final String d() {
        return "Error getting required ephemeral events fields. Using defaults.";
    }

    public static final String e() {
        return "Error getting required feature flag fields. Disabling feature flags.";
    }

    public static final String a(m mVar) {
        return android.support.v4.media.session.a.r(new StringBuilder("Banners enabled but maxBannerPlacement is "), mVar.G, ". Not enabling banners.");
    }

    public static final String i() {
        return "Error getting required SDK debugging fields. Disabling SDK debugging.";
    }

    public static final String a() {
        return "Error getting required banner configuration fields. Disabling banners.";
    }

    public static final String f() {
        return "Error getting required geofence fields. Using defaults.";
    }

    public static final String h() {
        return "Error getting required push max fields. Disabling push max.";
    }

    public static HashSet a(JSONObject jSONObject, String str) {
        Iterator c;
        HashSet hashSet = new HashSet();
        if (jSONObject.has(str)) {
            JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray(str);
            if (jSONArrayOptJSONArray == null) {
                K.a.getClass();
                c = J.a;
            } else {
                c = new C(q.h(q.e(CollectionsKt.D(kotlin.ranges.l.h(0, jSONArrayOptJSONArray.length())), new k(jSONArrayOptJSONArray)), new l(jSONArrayOptJSONArray)));
            }
            while (c.hasNext()) {
                hashSet.add((String) c.next());
            }
        }
        return hashSet;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public m(JSONObject configJson) throws JSONException {
        this();
        Intrinsics.checkNotNullParameter(configJson, "configJson");
        this.a = configJson.optLong("time", 0L);
        this.k = configJson.optLong("messaging_session_timeout", -1L);
        this.b = a(configJson, "events_blacklist");
        this.c = a(configJson, "attributes_blacklist");
        this.d = a(configJson, "purchases_blacklist");
        b(configJson);
        f(configJson);
        d(configJson);
        e(configJson);
        i(configJson);
        h(configJson);
        c(configJson);
        JSONObject jSONObjectOptJSONObject = configJson.optJSONObject("request_backoff");
        if (jSONObjectOptJSONObject != null) {
            this.v = jSONObjectOptJSONObject.optInt("min_sleep_duration_ms", this.v);
            this.w = jSONObjectOptJSONObject.optInt("max_sleep_duration_ms", this.w);
            this.x = jSONObjectOptJSONObject.optInt("scale_factor", this.x);
        }
        j(configJson);
        a(configJson);
    }
}
