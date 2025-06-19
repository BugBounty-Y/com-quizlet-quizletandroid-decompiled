package com.braze.storage;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.braze.managers.o0;
import com.braze.support.BrazeLogger;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class e0 {
    public static final int f = (int) TimeUnit.SECONDS.toMillis(10);
    public static final int g = (int) TimeUnit.MINUTES.toMillis(5);
    public final com.braze.events.d a;
    public final SharedPreferences b;
    public final ReentrantLock c;
    public final kotlinx.coroutines.sync.a d;
    public com.braze.models.response.m e;

    public e0(Context context, String apiKey, com.braze.events.d internalEventPublisher) {
        e0 e0Var;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        Intrinsics.checkNotNullParameter(internalEventPublisher, "internalEventPublisher");
        this.a = internalEventPublisher;
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.braze.storage.server_config.".concat(apiKey), 0);
        this.b = sharedPreferences;
        ReentrantLock reentrantLock = new ReentrantLock();
        this.c = reentrantLock;
        this.d = kotlinx.coroutines.sync.d.a();
        String string = sharedPreferences.getString("last_accessed_sdk_version", "");
        if ("36.0.0".equals(string)) {
            e0Var = this;
        } else {
            e0Var = this;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) e0Var, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.managers.C(string, 28), 6, (Object) null);
            sharedPreferences.edit().putLong("config_time", 0L).putString("last_accessed_sdk_version", "36.0.0").apply();
        }
        com.braze.models.response.m mVar = new com.braze.models.response.m();
        mVar.c = e();
        mVar.b = f();
        mVar.d = g();
        mVar.a = i();
        mVar.k = r();
        mVar.e = t();
        mVar.f = s();
        mVar.g = q();
        mVar.i = H();
        mVar.h = I();
        mVar.j = D();
        mVar.l = F();
        mVar.m = G();
        mVar.n = m();
        mVar.o = K();
        mVar.p = u();
        mVar.t = E();
        mVar.q = J();
        mVar.r = o();
        mVar.s = n();
        mVar.u = v();
        mVar.x = l();
        mVar.v = k();
        mVar.w = j();
        mVar.y = L();
        mVar.z = y();
        mVar.B = A();
        mVar.C = B();
        mVar.D = C();
        mVar.A = Long.valueOf(z());
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar2 = e0Var.e;
            Map mapW = (mVar2 == null || (mapW = mVar2.E) == null) ? w() : mapW;
            reentrantLock.unlock();
            mVar.E = mapW;
            mVar.F = d();
            mVar.G = p();
            reentrantLock.lock();
            try {
                e0Var.e = mVar;
                Unit unit = Unit.a;
            } finally {
                reentrantLock.unlock();
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public static final String N() {
        return "Attempting to unlock server config info";
    }

    public static final String O() {
        return "Unlocking config info lock.";
    }

    public static final String P() {
        return "Could not persist server config to shared preferences.";
    }

    public static final String Q() {
        return "Could not persist server config to shared preferences.";
    }

    public static final String R() {
        return "Server config is older than previous config time. Not sending out ConfigChangeEvent.";
    }

    public static final String a(String str, String str2) {
        return AbstractC0147y.e("Detected SDK update from '", str, "' -> '", str2, "'. Clearing config update time.");
    }

    public static final String b(com.braze.models.response.m mVar) {
        return "Finishing updating server config to " + mVar;
    }

    public static final String c() {
        return "Not allowing server config info unlock. Returning null.";
    }

    public static final String h() {
        return "Experienced exception retrieving blocklisted strings from local storage. Returning null.";
    }

    public static final String x() {
        return "Failed to parse endpoint override from storage";
    }

    public final long A() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            long j = mVar != null ? mVar.B : this.b.getLong("sdk_debugger_flush_interval_bytes", 0L);
            reentrantLock.unlock();
            return j;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final long B() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            long j = mVar != null ? mVar.C : this.b.getLong("sdk_debugger_flush_interval_seconds", 0L);
            reentrantLock.unlock();
            return j;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final long C() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            long j = mVar != null ? mVar.D : this.b.getLong("sdk_debugger_max_payload_bytes", 0L);
            reentrantLock.unlock();
            return j;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final boolean D() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            boolean z = mVar != null ? mVar.j : this.b.getBoolean("content_cards_enabled", false);
            reentrantLock.unlock();
            return z;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final boolean E() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            boolean z = mVar != null ? mVar.t : this.b.getBoolean("dust_enabled", false);
            reentrantLock.unlock();
            return z;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final boolean F() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            boolean z = mVar != null ? mVar.l : this.b.getBoolean("ephemeral_events_enabled", false);
            reentrantLock.unlock();
            return z;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final boolean G() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            boolean z = mVar != null ? mVar.m : this.b.getBoolean("feature_flags_enabled", false);
            reentrantLock.unlock();
            return z;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final boolean H() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            boolean z = mVar != null ? mVar.i : this.b.getBoolean("geofences_enabled", false);
            reentrantLock.unlock();
            return z;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final boolean I() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            boolean z = mVar != null ? mVar.h : this.b.getBoolean("geofences_enabled_set", false);
            reentrantLock.unlock();
            return z;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final boolean J() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            boolean z = mVar != null ? mVar.q : this.b.getBoolean("global_req_rate_limit_enabled", true);
            reentrantLock.unlock();
            return z;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final boolean K() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            boolean z = mVar != null ? mVar.o : this.b.getBoolean("push_max_enabled", false);
            reentrantLock.unlock();
            return z;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final boolean L() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            boolean z = mVar != null ? mVar.y : this.b.getBoolean("sdk_debugger_enabled", false);
            reentrantLock.unlock();
            return z;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final void M() {
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.requests.y(27), 6, (Object) null);
        kotlinx.coroutines.sync.c cVar = (kotlinx.coroutines.sync.c) this.d;
        cVar.getClass();
        if (Math.max(kotlinx.coroutines.sync.h.g.get(cVar), 0) == 0) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.requests.y(28), 7, (Object) null);
            ((kotlinx.coroutines.sync.c) this.d).f(null);
        }
    }

    public final boolean d() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            boolean z = mVar != null ? mVar.F : this.b.getBoolean("banners_enabled", false);
            reentrantLock.unlock();
            return z;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final Set e() {
        Set setA;
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            if (mVar == null || (setA = mVar.c) == null) {
                setA = a("blacklisted_attributes");
            }
            reentrantLock.unlock();
            return setA;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final Set f() {
        Set setA;
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            if (mVar == null || (setA = mVar.b) == null) {
                setA = a("blacklisted_events");
            }
            reentrantLock.unlock();
            return setA;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final Set g() {
        Set setA;
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            if (mVar == null || (setA = mVar.d) == null) {
                setA = a("blacklisted_purchases");
            }
            reentrantLock.unlock();
            return setA;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final long i() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            long j = mVar != null ? mVar.a : this.b.getLong("config_time", 0L);
            reentrantLock.unlock();
            return j;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final int j() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            int i = mVar != null ? mVar.w : this.b.getInt("default_backoff_max_sleep_duration_ms", g);
            reentrantLock.unlock();
            return i;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final int k() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            int i = mVar != null ? mVar.v : this.b.getInt("default_backoff_min_sleep_duration__ms", f);
            reentrantLock.unlock();
            return i;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final int l() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            int i = mVar != null ? mVar.x : this.b.getInt("default_backoff_scale_factor", 3);
            reentrantLock.unlock();
            return i;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final int m() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            int i = mVar != null ? mVar.n : this.b.getInt("feature_flags_refresh_rate_limit", -1);
            reentrantLock.unlock();
            return i;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final int n() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            int i = mVar != null ? mVar.s : this.b.getInt("global_req_rate_capacity", 30);
            reentrantLock.unlock();
            return i;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final int o() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            int i = mVar != null ? mVar.r : this.b.getInt("global_req_rate_refill_rate", 30);
            reentrantLock.unlock();
            return i;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final int p() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            int i = mVar != null ? mVar.G : this.b.getInt("max_banner_placements", 0);
            reentrantLock.unlock();
            return i;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final int q() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            int i = mVar != null ? mVar.g : this.b.getInt("geofences_max_num_to_register", -1);
            reentrantLock.unlock();
            return i;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final long r() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            long j = mVar != null ? mVar.k : this.b.getLong("messaging_session_timeout", -1L);
            reentrantLock.unlock();
            return j;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final int s() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            int i = mVar != null ? mVar.f : this.b.getInt("geofences_min_time_since_last_report", -1);
            reentrantLock.unlock();
            return i;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final int t() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            int i = mVar != null ? mVar.e : this.b.getInt("geofences_min_time_since_last_request", -1);
            reentrantLock.unlock();
            return i;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final long u() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            long j = mVar != null ? mVar.p : this.b.getLong("push_max_redeliver_buffer", 86400L);
            reentrantLock.unlock();
            return j;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final long v() {
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            long j = mVar != null ? mVar.u : this.b.getLong("push_max_redeliver_dedupe_buffer", -1L);
            reentrantLock.unlock();
            return j;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final LinkedHashMap w() throws JSONException {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        try {
            String string = this.b.getString("global_req_rate_limit_endpoint_overrides", "");
            if (string != null && string.length() != 0) {
                JSONObject jSONObject = new JSONObject(string);
                Iterator<String> itKeys = jSONObject.keys();
                Intrinsics.checkNotNullExpressionValue(itKeys, "keys(...)");
                while (itKeys.hasNext()) {
                    String next = itKeys.next();
                    com.braze.requests.l lVar = com.braze.requests.m.b;
                    Intrinsics.d(next);
                    com.braze.requests.m mVarA = lVar.a(next);
                    if (mVarA != null) {
                        JSONObject jSONObject2 = jSONObject.getJSONObject(next);
                        linkedHashMap.put(mVarA, new com.braze.models.response.j(jSONObject2.getInt("capacity"), jSONObject2.getInt("refill")));
                    }
                }
            }
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new B(2), 4, (Object) null);
        }
        return linkedHashMap;
    }

    public final String y() {
        String string;
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            if (mVar == null || (string = mVar.z) == null) {
                string = this.b.getString("sdk_debugger_authorization_code", null);
            }
            reentrantLock.unlock();
            return string;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final long z() {
        Long l;
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            long j = (mVar == null || (l = mVar.A) == null) ? this.b.getLong("sdk_debugger_expiration_time", -1L) : l.longValue();
            reentrantLock.unlock();
            return j;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public static final String b() {
        return "Attempting to acquire server config lock";
    }

    public final void a(com.braze.models.response.m serverConfig) throws JSONException {
        Intrinsics.checkNotNullParameter(serverConfig, "serverConfig");
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            this.e = serverConfig;
            Unit unit = Unit.a;
            try {
                SharedPreferences.Editor editorEdit = this.b.edit();
                if (serverConfig.b != null) {
                    editorEdit.putString("blacklisted_events", new JSONArray((Collection) serverConfig.b).toString());
                }
                if (serverConfig.c != null) {
                    editorEdit.putString("blacklisted_attributes", new JSONArray((Collection) serverConfig.c).toString());
                }
                if (serverConfig.d != null) {
                    editorEdit.putString("blacklisted_purchases", new JSONArray((Collection) serverConfig.d).toString());
                }
                Map map = serverConfig.E;
                if (map != null) {
                    JSONObject jSONObject = new JSONObject();
                    for (com.braze.requests.m mVar2 : map.keySet()) {
                        com.braze.models.response.j jVar = (com.braze.models.response.j) map.get(mVar2);
                        if (jVar != null) {
                            jSONObject.put(mVar2.name(), new JSONObject().put("refill", jVar.b).put("capacity", jVar.a));
                        }
                    }
                    editorEdit.putString("global_req_rate_limit_endpoint_overrides", jSONObject.toString());
                }
                editorEdit.putLong("config_time", serverConfig.a).putInt("geofences_min_time_since_last_request", serverConfig.e).putInt("geofences_min_time_since_last_report", serverConfig.f).putInt("geofences_max_num_to_register", serverConfig.g).putBoolean("geofences_enabled", serverConfig.i).putBoolean("geofences_enabled_set", serverConfig.h).putLong("messaging_session_timeout", serverConfig.k).putBoolean("ephemeral_events_enabled", serverConfig.l).putBoolean("feature_flags_enabled", serverConfig.m).putInt("feature_flags_refresh_rate_limit", serverConfig.n).putBoolean("content_cards_enabled", serverConfig.j).putBoolean("push_max_enabled", serverConfig.o).putLong("push_max_redeliver_buffer", serverConfig.p).putBoolean("dust_enabled", serverConfig.t).putBoolean("global_req_rate_limit_enabled", serverConfig.q).putInt("global_req_rate_capacity", serverConfig.s).putInt("global_req_rate_refill_rate", serverConfig.r).putLong("push_max_redeliver_dedupe_buffer", serverConfig.u).putInt("default_backoff_scale_factor", serverConfig.x).putInt("default_backoff_min_sleep_duration__ms", serverConfig.v).putInt("default_backoff_max_sleep_duration_ms", serverConfig.w).putBoolean("sdk_debugger_enabled", serverConfig.y).putString("sdk_debugger_authorization_code", serverConfig.z).putLong("sdk_debugger_flush_interval_bytes", serverConfig.B).putLong("sdk_debugger_flush_interval_seconds", serverConfig.C).putLong("sdk_debugger_max_payload_bytes", serverConfig.D).putBoolean("banners_enabled", serverConfig.F).putInt("max_banner_placements", serverConfig.G);
                Long l = serverConfig.A;
                if (l != null) {
                    editorEdit.putLong("sdk_debugger_expiration_time", l.longValue());
                }
                editorEdit.apply();
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.requests.y(26), 4, (Object) null);
            }
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.models.response.p(serverConfig, 1), 6, (Object) null);
            if (mVar != null) {
                if (serverConfig.a > mVar.a) {
                    this.a.b(new com.braze.events.internal.d(mVar, serverConfig), com.braze.events.internal.d.class);
                } else {
                    BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.requests.y(29), 7, (Object) null);
                }
            }
        } finally {
            reentrantLock.unlock();
        }
    }

    public final void a(o0 sdkDebugConfig) {
        Intrinsics.checkNotNullParameter(sdkDebugConfig, "sdkDebugConfig");
        ReentrantLock reentrantLock = this.c;
        reentrantLock.lock();
        try {
            com.braze.models.response.m mVar = this.e;
            if (mVar != null) {
                mVar.y = sdkDebugConfig.a;
            }
            if (mVar != null) {
                mVar.B = sdkDebugConfig.d;
            }
            if (mVar != null) {
                mVar.C = sdkDebugConfig.e;
            }
            if (mVar != null) {
                mVar.D = sdkDebugConfig.f;
            }
            String str = sdkDebugConfig.c;
            if (str != null && mVar != null) {
                mVar.z = str;
            }
            Long l = sdkDebugConfig.b;
            if (l != null) {
                long jLongValue = l.longValue();
                com.braze.models.response.m mVar2 = this.e;
                if (mVar2 != null) {
                    mVar2.A = Long.valueOf(jLongValue);
                }
                Unit unit = Unit.a;
            }
            reentrantLock.unlock();
            try {
                com.braze.models.response.m mVar3 = this.e;
                if (mVar3 != null) {
                    SharedPreferences.Editor editorEdit = this.b.edit();
                    editorEdit.putBoolean("sdk_debugger_enabled", mVar3.y).putString("sdk_debugger_authorization_code", mVar3.z).putLong("sdk_debugger_flush_interval_bytes", mVar3.B).putLong("sdk_debugger_flush_interval_seconds", mVar3.C).putLong("sdk_debugger_max_payload_bytes", mVar3.D);
                    Long l2 = mVar3.A;
                    if (l2 != null) {
                        editorEdit.putLong("sdk_debugger_expiration_time", l2.longValue());
                    }
                    editorEdit.apply();
                }
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new B(4), 4, (Object) null);
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.requests.framework.o(this, 5), 6, (Object) null);
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public static final String a(e0 e0Var) {
        return "Finishing updating server config to " + e0Var.e;
    }

    public final Pair a() {
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.Priority priority = BrazeLogger.Priority.V;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new B(0), 6, (Object) null);
        if (!((kotlinx.coroutines.sync.c) this.d).e()) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new B(1), 6, (Object) null);
            return null;
        }
        return new Pair(Long.valueOf(i()), Boolean.valueOf(i() <= 0));
    }

    public final HashSet a(String str) {
        try {
            String string = this.b.getString(str, "");
            HashSet hashSet = new HashSet();
            if (string != null && !StringsKt.O(string)) {
                JSONArray jSONArray = new JSONArray(string);
                kotlin.sequences.t tVarH = kotlin.sequences.q.h(kotlin.sequences.q.e(CollectionsKt.D(kotlin.ranges.l.h(0, jSONArray.length())), new c0(jSONArray)), new d0(jSONArray));
                Iterator it2 = tVarH.b.iterator();
                while (it2.hasNext()) {
                    hashSet.add((String) tVarH.c.invoke(it2.next()));
                }
            }
            return hashSet;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new B(3), 4, (Object) null);
            return new HashSet();
        }
    }
}
