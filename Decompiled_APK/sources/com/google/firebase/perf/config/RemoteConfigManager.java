package com.google.firebase.perf.config;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageManager;
import androidx.annotation.Keep;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

@Keep
/* loaded from: classes2.dex */
public class RemoteConfigManager {
    private static final long FETCH_NEVER_HAPPENED_TIMESTAMP_MS = 0;
    private static final String FIREPERF_FRC_NAMESPACE_NAME = "fireperf";
    private static final long MIN_APP_START_CONFIG_FETCH_DELAY_MS = 5000;
    private static final int RANDOM_APP_START_CONFIG_FETCH_DELAY_MS = 25000;
    private final ConcurrentHashMap<String, com.google.firebase.remoteconfig.c> allRcConfigMap;
    private final long appStartConfigFetchDelayInMs;
    private final long appStartTimeInMs;
    private final v cache;
    private final Executor executor;
    private com.google.firebase.remoteconfig.b firebaseRemoteConfig;
    private long firebaseRemoteConfigLastFetchTimestampMs;
    private com.google.firebase.inject.b firebaseRemoteConfigProvider;
    private static final com.google.firebase.perf.logging.a logger = com.google.firebase.perf.logging.a.d();
    private static final RemoteConfigManager instance = new RemoteConfigManager();
    private static final long TIME_AFTER_WHICH_A_FETCH_IS_CONSIDERED_STALE_MS = TimeUnit.HOURS.toMillis(12);

    @SuppressLint({"ThreadPoolCreation"})
    private RemoteConfigManager() {
        this(v.b(), new ThreadPoolExecutor(0, 1, FETCH_NEVER_HAPPENED_TIMESTAMP_MS, TimeUnit.SECONDS, new LinkedBlockingQueue()), null, new Random().nextInt(RANDOM_APP_START_CONFIG_FETCH_DELAY_MS) + MIN_APP_START_CONFIG_FETCH_DELAY_MS, getInitialStartupMillis());
    }

    public static long getInitialStartupMillis() {
        com.google.firebase.a aVar;
        try {
            aVar = (com.google.firebase.a) com.google.firebase.h.c().b(com.google.firebase.a.class);
        } catch (IllegalStateException unused) {
            logger.a();
            aVar = null;
        }
        return aVar != null ? aVar.a : System.currentTimeMillis();
    }

    public static RemoteConfigManager getInstance() {
        return instance;
    }

    private com.google.firebase.remoteconfig.c getRemoteConfigValue(String str) {
        triggerRemoteConfigFetchIfNecessary();
        if (!isFirebaseRemoteConfigAvailable() || !this.allRcConfigMap.containsKey(str)) {
            return null;
        }
        com.google.firebase.remoteconfig.c cVar = this.allRcConfigMap.get(str);
        com.google.firebase.remoteconfig.internal.l lVar = (com.google.firebase.remoteconfig.internal.l) cVar;
        if (lVar.b != 2) {
            return null;
        }
        logger.b("Fetched value: '%s' for key: '%s' from Firebase Remote Config.", lVar.d(), str);
        return cVar;
    }

    public static int getVersionCode(Context context) {
        try {
            return context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionCode;
        } catch (PackageManager.NameNotFoundException unused) {
            return 0;
        }
    }

    private boolean hasAppStartConfigFetchDelayElapsed(long j) {
        return j - this.appStartTimeInMs >= this.appStartConfigFetchDelayInMs;
    }

    private boolean hasLastFetchBecomeStale(long j) {
        return j - this.firebaseRemoteConfigLastFetchTimestampMs > TIME_AFTER_WHICH_A_FETCH_IS_CONSIDERED_STALE_MS;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$triggerFirebaseRemoteConfigFetchAndActivateOnSuccessfulFetch$0(Boolean bool) {
        syncConfigValues(this.firebaseRemoteConfig.a());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$triggerFirebaseRemoteConfigFetchAndActivateOnSuccessfulFetch$1(Exception exc) {
        logger.g("Call to Remote Config failed: %s. This may cause a degraded experience with Firebase Performance. Please reach out to Firebase Support https://firebase.google.com/support/", exc);
        this.firebaseRemoteConfigLastFetchTimestampMs = FETCH_NEVER_HAPPENED_TIMESTAMP_MS;
    }

    private boolean shouldFetchAndActivateRemoteConfigValues() {
        long currentSystemTimeMillis = getCurrentSystemTimeMillis();
        return hasAppStartConfigFetchDelayElapsed(currentSystemTimeMillis) && hasLastFetchBecomeStale(currentSystemTimeMillis);
    }

    private void triggerFirebaseRemoteConfigFetchAndActivateOnSuccessfulFetch() {
        this.firebaseRemoteConfigLastFetchTimestampMs = getCurrentSystemTimeMillis();
        com.google.firebase.remoteconfig.b bVar = this.firebaseRemoteConfig;
        com.google.firebase.remoteconfig.internal.e eVar = bVar.e;
        com.google.firebase.remoteconfig.internal.j jVar = eVar.g;
        long j = jVar.a.getLong("minimum_fetch_interval_in_seconds", com.google.firebase.remoteconfig.internal.e.i);
        HashMap map = new HashMap(eVar.h);
        map.put("X-Firebase-RC-Fetch-Type", "BASE/1");
        eVar.e.b().f(eVar.c, new androidx.camera.core.impl.utils.futures.e(eVar, j, map, 4)).n(com.google.firebase.concurrent.h.a, new com.google.firebase.components.n(24)).n(bVar.b, new com.google.firebase.remoteconfig.a(bVar)).d(this.executor, new w(this)).c(this.executor, new w(this));
    }

    private void triggerRemoteConfigFetchIfNecessary() {
        if (isFirebaseRemoteConfigAvailable()) {
            if (this.allRcConfigMap.isEmpty()) {
                this.allRcConfigMap.putAll(this.firebaseRemoteConfig.a());
            }
            if (shouldFetchAndActivateRemoteConfigValues()) {
                triggerFirebaseRemoteConfigFetchAndActivateOnSuccessfulFetch();
            }
        }
    }

    public com.google.firebase.perf.util.d getBoolean(String str) {
        if (str == null) {
            logger.a();
            return new com.google.firebase.perf.util.d();
        }
        com.google.firebase.remoteconfig.c remoteConfigValue = getRemoteConfigValue(str);
        if (remoteConfigValue != null) {
            try {
                return new com.google.firebase.perf.util.d(Boolean.valueOf(((com.google.firebase.remoteconfig.internal.l) remoteConfigValue).a()));
            } catch (IllegalArgumentException unused) {
                com.google.firebase.remoteconfig.internal.l lVar = (com.google.firebase.remoteconfig.internal.l) remoteConfigValue;
                if (!lVar.d().isEmpty()) {
                    logger.b("Could not parse value: '%s' for key: '%s'.", lVar.d(), str);
                }
            }
        }
        return new com.google.firebase.perf.util.d();
    }

    public long getCurrentSystemTimeMillis() {
        return System.currentTimeMillis();
    }

    public com.google.firebase.perf.util.d getDouble(String str) {
        if (str == null) {
            logger.a();
            return new com.google.firebase.perf.util.d();
        }
        com.google.firebase.remoteconfig.c remoteConfigValue = getRemoteConfigValue(str);
        if (remoteConfigValue != null) {
            try {
                return new com.google.firebase.perf.util.d(Double.valueOf(((com.google.firebase.remoteconfig.internal.l) remoteConfigValue).b()));
            } catch (IllegalArgumentException unused) {
                com.google.firebase.remoteconfig.internal.l lVar = (com.google.firebase.remoteconfig.internal.l) remoteConfigValue;
                if (!lVar.d().isEmpty()) {
                    logger.b("Could not parse value: '%s' for key: '%s'.", lVar.d(), str);
                }
            }
        }
        return new com.google.firebase.perf.util.d();
    }

    public com.google.firebase.perf.util.d getLong(String str) {
        if (str == null) {
            logger.a();
            return new com.google.firebase.perf.util.d();
        }
        com.google.firebase.remoteconfig.c remoteConfigValue = getRemoteConfigValue(str);
        if (remoteConfigValue != null) {
            try {
                return new com.google.firebase.perf.util.d(Long.valueOf(((com.google.firebase.remoteconfig.internal.l) remoteConfigValue).c()));
            } catch (IllegalArgumentException unused) {
                com.google.firebase.remoteconfig.internal.l lVar = (com.google.firebase.remoteconfig.internal.l) remoteConfigValue;
                if (!lVar.d().isEmpty()) {
                    logger.b("Could not parse value: '%s' for key: '%s'.", lVar.d(), str);
                }
            }
        }
        return new com.google.firebase.perf.util.d();
    }

    public <T> T getRemoteConfigValueOrDefault(String str, T t) {
        com.google.firebase.remoteconfig.c remoteConfigValue = getRemoteConfigValue(str);
        if (remoteConfigValue != null) {
            try {
                if (t instanceof Boolean) {
                    return (T) Boolean.valueOf(((com.google.firebase.remoteconfig.internal.l) remoteConfigValue).a());
                }
                if (t instanceof Double) {
                    return (T) Double.valueOf(((com.google.firebase.remoteconfig.internal.l) remoteConfigValue).b());
                }
                if (!(t instanceof Long) && !(t instanceof Integer)) {
                    if (t instanceof String) {
                        return (T) ((com.google.firebase.remoteconfig.internal.l) remoteConfigValue).d();
                    }
                    T t2 = (T) ((com.google.firebase.remoteconfig.internal.l) remoteConfigValue).d();
                    try {
                        logger.b("No matching type found for the defaultValue: '%s', using String.", t);
                        return t2;
                    } catch (IllegalArgumentException unused) {
                        t = t2;
                        com.google.firebase.remoteconfig.internal.l lVar = (com.google.firebase.remoteconfig.internal.l) remoteConfigValue;
                        if (!lVar.d().isEmpty()) {
                            logger.b("Could not parse value: '%s' for key: '%s'.", lVar.d(), str);
                        }
                        return t;
                    }
                }
                return (T) Long.valueOf(((com.google.firebase.remoteconfig.internal.l) remoteConfigValue).c());
            } catch (IllegalArgumentException unused2) {
            }
        }
        return t;
    }

    public com.google.firebase.perf.util.d getString(String str) {
        if (str == null) {
            logger.a();
            return new com.google.firebase.perf.util.d();
        }
        com.google.firebase.remoteconfig.c remoteConfigValue = getRemoteConfigValue(str);
        return remoteConfigValue != null ? new com.google.firebase.perf.util.d(((com.google.firebase.remoteconfig.internal.l) remoteConfigValue).d()) : new com.google.firebase.perf.util.d();
    }

    public boolean isFirebaseRemoteConfigAvailable() {
        com.google.firebase.inject.b bVar;
        com.google.firebase.remoteconfig.f fVar;
        if (this.firebaseRemoteConfig == null && (bVar = this.firebaseRemoteConfigProvider) != null && (fVar = (com.google.firebase.remoteconfig.f) bVar.get()) != null) {
            this.firebaseRemoteConfig = fVar.b(FIREPERF_FRC_NAMESPACE_NAME);
        }
        return this.firebaseRemoteConfig != null;
    }

    public boolean isLastFetchFailed() {
        com.google.firebase.remoteconfig.b bVar = this.firebaseRemoteConfig;
        return bVar == null || bVar.b().b == 1 || this.firebaseRemoteConfig.b().b == 2;
    }

    public void setFirebaseRemoteConfigProvider(com.google.firebase.inject.b bVar) {
        this.firebaseRemoteConfigProvider = bVar;
    }

    public void syncConfigValues(Map<String, com.google.firebase.remoteconfig.c> map) {
        this.allRcConfigMap.putAll(map);
        for (String str : this.allRcConfigMap.keySet()) {
            if (!map.containsKey(str)) {
                this.allRcConfigMap.remove(str);
            }
        }
        d dVarC = d.c();
        ConcurrentHashMap<String, com.google.firebase.remoteconfig.c> concurrentHashMap = this.allRcConfigMap;
        dVarC.getClass();
        com.google.firebase.remoteconfig.c cVar = concurrentHashMap.get("fpr_experiment_app_start_ttid");
        if (cVar == null) {
            logger.a();
            return;
        }
        try {
            this.cache.g("com.google.firebase.perf.ExperimentTTID", ((com.google.firebase.remoteconfig.internal.l) cVar).a());
        } catch (Exception unused) {
            logger.a();
        }
    }

    public RemoteConfigManager(v vVar, Executor executor, com.google.firebase.remoteconfig.b bVar, long j, long j2) {
        ConcurrentHashMap<String, com.google.firebase.remoteconfig.c> concurrentHashMap;
        this.firebaseRemoteConfigLastFetchTimestampMs = FETCH_NEVER_HAPPENED_TIMESTAMP_MS;
        this.cache = vVar;
        this.executor = executor;
        this.firebaseRemoteConfig = bVar;
        if (bVar == null) {
            concurrentHashMap = new ConcurrentHashMap<>();
        } else {
            concurrentHashMap = new ConcurrentHashMap<>(bVar.a());
        }
        this.allRcConfigMap = concurrentHashMap;
        this.appStartTimeInMs = j2;
        this.appStartConfigFetchDelayInMs = j;
    }
}
