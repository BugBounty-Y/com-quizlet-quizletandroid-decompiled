package com.braze.managers;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.navigation.compose.C1277j;
import com.braze.AbstractC1475a;
import com.braze.AbstractC1484j;
import com.braze.events.IEventSubscriber;
import com.braze.models.BrazeGeofence;
import com.braze.support.BrazeLogger;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;

/* renamed from: com.braze.managers.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1496i {
    public final SharedPreferences a;
    public final SharedPreferences b;
    public final ConcurrentHashMap c;
    public final AtomicBoolean d;
    public long e;
    public long f;
    public int g;
    public int h;

    public C1496i(Context context, String apiKey, com.braze.storage.e0 serverConfigStorageProvider, com.braze.events.e internalIEventMessenger) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        Intrinsics.checkNotNullParameter(internalIEventMessenger, "internalIEventMessenger");
        ((com.braze.events.d) internalIEventMessenger).c(com.braze.events.internal.y.class, (IEventSubscriber) new com.braze.dispatch.m(this, 1));
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.appboy.managers.geofences.eligibility.global." + apiKey, 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        this.a = sharedPreferences;
        SharedPreferences sharedPreferences2 = context.getSharedPreferences("com.appboy.managers.geofences.eligibility.individual." + apiKey, 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences2, "getSharedPreferences(...)");
        this.b = sharedPreferences2;
        this.c = a(sharedPreferences2);
        this.d = new AtomicBoolean(false);
        this.e = sharedPreferences.getLong("last_request_global", 0L);
        this.f = sharedPreferences.getLong("last_report_global", 0L);
        this.g = serverConfigStorageProvider.t();
        this.h = serverConfigStorageProvider.s();
    }

    public static final String b(String str) {
        return AbstractC1484j.a("Exception trying to parse re-eligibility id: ", str);
    }

    public static final String c(String str) {
        return AbstractC1475a.a("Deleting outdated id ", str, " from re-eligibility list.");
    }

    public static final String d(String str) {
        return AbstractC1475a.a("Retaining id ", str, " in re-eligibility list.");
    }

    public final void a(com.braze.models.response.m serverConfig) {
        Intrinsics.checkNotNullParameter(serverConfig, "serverConfig");
        int i = serverConfig.e;
        if (i >= 0) {
            this.g = i;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.enums.i(i, 1), 6, (Object) null);
        }
        int i2 = serverConfig.f;
        if (i2 >= 0) {
            this.h = i2;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.enums.i(i2, 2), 6, (Object) null);
        }
    }

    public static final String b(long j, C1496i c1496i) {
        return android.support.v4.media.session.a.r(androidx.compose.animation.d0.t(j, "Geofence request suppressed since only ", " seconds have passed since the last time geofences were requested (minimum interval: "), c1496i.g, ").");
    }

    public static final String c(long j) {
        return androidx.compose.animation.d0.n(j, "Updating the last successful location request time to: ");
    }

    public static final void a(C1496i c1496i, com.braze.events.internal.y it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        c1496i.d.set(false);
    }

    public final void a(List brazeGeofenceList) {
        Intrinsics.checkNotNullParameter(brazeGeofenceList, "brazeGeofenceList");
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        Iterator it2 = brazeGeofenceList.iterator();
        while (it2.hasNext()) {
            linkedHashSet.add(((BrazeGeofence) it2.next()).getId());
        }
        HashSet hashSet = new HashSet(this.c.keySet());
        SharedPreferences.Editor editorEdit = this.b.edit();
        Iterator it3 = hashSet.iterator();
        Intrinsics.checkNotNullExpressionValue(it3, "iterator(...)");
        while (it3.hasNext()) {
            String str = (String) it3.next();
            Intrinsics.d(str);
            if (!linkedHashSet.contains(a(str))) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C(str, 6), 7, (Object) null);
                this.c.remove(str);
                editorEdit.remove(str);
            } else {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C(str, 7), 7, (Object) null);
            }
        }
        editorEdit.apply();
    }

    public static final String b() {
        return "Geofences have already been requested for the current session. Geofence request not eligible.";
    }

    public final void b(long j) {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.dispatch.j(3, j), 7, (Object) null);
        this.e = j;
        this.a.edit().putLong("last_request_global", this.e).apply();
    }

    public static final String b(int i) {
        return androidx.compose.animation.d0.m('.', i, "Min time since last geofence report reset via server configuration: ");
    }

    public final boolean a(boolean z, long j) {
        final long j2 = j - this.e;
        if (!z && this.g > j2) {
            final int i = 0;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, new Function0() { // from class: com.braze.managers.I
                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    switch (i) {
                        case 0:
                            return C1496i.b(j2, this);
                        default:
                            return C1496i.a(j2, this);
                    }
                }
            }, 7, (Object) null);
            return false;
        }
        if (z) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.dispatch.j(4, j2), 7, (Object) null);
        } else {
            final int i2 = 1;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, new Function0() { // from class: com.braze.managers.I
                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    switch (i2) {
                        case 0:
                            return C1496i.b(j2, this);
                        default:
                            return C1496i.a(j2, this);
                    }
                }
            }, 7, (Object) null);
        }
        if (this.d.compareAndSet(false, true)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(19), 7, (Object) null);
            return true;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(20), 7, (Object) null);
        return false;
    }

    public static final String a(long j) {
        return androidx.compose.animation.d0.n(j, "Ignoring rate limit for this geofence request. Elapsed time since last request:");
    }

    public static final String a(long j, C1496i c1496i) {
        StringBuilder sb = new StringBuilder();
        sb.append(j);
        sb.append(" seconds have passed since the last time geofences were requested (minimum interval: ");
        return android.support.v4.media.session.a.r(sb, c1496i.g, ").");
    }

    public static final String a() {
        return "Geofences have not been requested for the current session yet. Request is eligible.";
    }

    public final String a(String reEligibilityId) {
        Intrinsics.checkNotNullParameter(reEligibilityId, "reEligibilityId");
        try {
            return (String) new Regex("_").g(2, reEligibilityId).get(1);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new C(reEligibilityId, 8), 4, (Object) null);
            return null;
        }
    }

    public static final String a(int i) {
        return androidx.compose.animation.d0.m('.', i, "Min time since last geofence request reset via server configuration: ");
    }

    public final ConcurrentHashMap a(SharedPreferences sharedPreferences) {
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        ConcurrentHashMap concurrentHashMap = new ConcurrentHashMap();
        Map<String, ?> all = sharedPreferences.getAll();
        if (all != null && !all.isEmpty()) {
            Set<String> setKeySet = all.keySet();
            if (!setKeySet.isEmpty()) {
                for (String str : setKeySet) {
                    long j = sharedPreferences.getLong(str, 0L);
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1277j(8, this, str), 7, (Object) null);
                    concurrentHashMap.put(str, Long.valueOf(j));
                }
            }
        }
        return concurrentHashMap;
    }

    public static final String a(C1496i c1496i, String str) {
        StringBuilder sb = new StringBuilder("Retrieving geofence id ");
        Intrinsics.d(str);
        sb.append(c1496i.a(str));
        sb.append(" eligibility information from local storage.");
        return sb.toString();
    }
}
