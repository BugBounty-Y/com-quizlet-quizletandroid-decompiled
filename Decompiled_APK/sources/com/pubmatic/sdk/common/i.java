package com.pubmatic.sdk.common;

import android.app.Application;
import android.content.Context;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.network.n;
import com.pubmatic.sdk.common.utility.o;
import com.pubmatic.sdk.monitor.POBMonitor;
import java.lang.reflect.Method;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class i {
    private static volatile com.pubmatic.sdk.common.models.f a;
    private static volatile com.pubmatic.sdk.common.models.c b;
    private static volatile com.pubmatic.sdk.common.utility.g c;
    private static volatile com.pubmatic.sdk.common.network.g d;
    private static volatile j e;
    private static volatile com.pubmatic.sdk.common.cache.b f;
    private static volatile n g;
    private static volatile com.pubmatic.sdk.common.network.i h;
    private static volatile com.pubmatic.sdk.common.cache.a i;

    public class a implements com.pubmatic.sdk.common.network.d {
        @Override // com.pubmatic.sdk.common.network.d
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public void onSuccess(JSONObject jSONObject) {
            if (jSONObject != null) {
                String version = com.pubmatic.sdk.common.a.getVersion();
                if (version.compareTo(jSONObject.optString("latest_ver", version)) < 0) {
                    POBLog.info("POBInstanceProvider", jSONObject.optString("message"), new Object[0]);
                }
            }
        }

        @Override // com.pubmatic.sdk.common.network.d
        public void onFailure(@NonNull h hVar) {
            POBLog.debug("POBInstanceProvider", hVar.getErrorMessage(), new Object[0]);
        }
    }

    static {
        try {
            Method method = POBMonitor.class.getMethod("load", null);
            method.setAccessible(true);
            method.invoke(null, null);
        } catch (Exception e2) {
            POBLog.error("POBInstanceProvider", e2.getMessage(), new Object[0]);
        }
        try {
            Context applicationContext = ((Application) Class.forName("android.app.ActivityThread").getMethod("currentApplication", null).invoke(null, null)).getApplicationContext();
            Boolean bool = (Boolean) o.getBuildConfigValue(applicationContext, "DEBUG");
            if (bool == null || !bool.booleanValue()) {
                return;
            }
            a(applicationContext);
        } catch (Exception e3) {
            POBLog.error("POBInstanceProvider", e3.getMessage(), new Object[0]);
        }
    }

    private static void a(@NonNull Context context) {
        com.pubmatic.sdk.common.network.g networkHandler = getNetworkHandler(context);
        com.pubmatic.sdk.common.network.a aVar = new com.pubmatic.sdk.common.network.a();
        aVar.setUrl("https://repo.pubmatic.com/artifactory/public-repos/apis/android/ow-sdk/release.json");
        networkHandler.sendJSONRequest(aVar, new a());
    }

    @NonNull
    public static com.pubmatic.sdk.common.cache.a getAdViewCacheService() {
        if (i == null) {
            synchronized (com.pubmatic.sdk.common.cache.a.class) {
                try {
                    if (i == null) {
                        i = new com.pubmatic.sdk.common.cache.a();
                    }
                } finally {
                }
            }
        }
        return i;
    }

    @NonNull
    public static com.pubmatic.sdk.common.models.c getAppInfo(@NonNull Context context) {
        if (b == null) {
            synchronized (com.pubmatic.sdk.common.models.c.class) {
                try {
                    if (b == null) {
                        b = new com.pubmatic.sdk.common.models.c(context);
                    }
                } finally {
                }
            }
        }
        return b;
    }

    @NonNull
    public static com.pubmatic.sdk.common.cache.b getCacheManager(@NonNull Context context) {
        if (f == null) {
            synchronized (com.pubmatic.sdk.common.cache.b.class) {
                try {
                    if (f == null) {
                        f = new com.pubmatic.sdk.common.cache.b(context, getNetworkHandler(context));
                    }
                } finally {
                }
            }
        }
        return f;
    }

    @NonNull
    public static com.pubmatic.sdk.common.models.f getDeviceInfo(@NonNull Context context) {
        if (a == null) {
            synchronized (com.pubmatic.sdk.common.models.f.class) {
                try {
                    if (a == null) {
                        a = new com.pubmatic.sdk.common.models.f(context);
                    }
                } finally {
                }
            }
        }
        return a;
    }

    @NonNull
    public static com.pubmatic.sdk.common.utility.g getLocationDetector(@NonNull Context context) {
        if (c == null) {
            synchronized (com.pubmatic.sdk.common.utility.g.class) {
                try {
                    if (c == null) {
                        c = new com.pubmatic.sdk.common.utility.g(context);
                        c.setLocationUpdateIntervalInMs(getSdkConfig().getLocationDetectionDurationInMillis());
                    }
                } finally {
                }
            }
        }
        return c;
    }

    @NonNull
    public static com.pubmatic.sdk.common.network.g getNetworkHandler(@NonNull Context context) {
        if (d == null) {
            synchronized (com.pubmatic.sdk.common.network.g.class) {
                try {
                    if (d == null) {
                        d = new com.pubmatic.sdk.common.network.g(context);
                    }
                } finally {
                }
            }
        }
        return d;
    }

    @NonNull
    public static com.pubmatic.sdk.common.network.i getNetworkMonitor(@NonNull Context context) {
        if (h == null) {
            synchronized (com.pubmatic.sdk.common.network.i.class) {
                try {
                    if (h == null) {
                        h = new com.pubmatic.sdk.common.network.i(context);
                    }
                } finally {
                }
            }
        }
        return h;
    }

    @NonNull
    public static j getSdkConfig() {
        if (e == null) {
            synchronized (com.pubmatic.sdk.common.network.g.class) {
                try {
                    if (e == null) {
                        e = new j();
                    }
                } finally {
                }
            }
        }
        return e;
    }

    @NonNull
    public static n getTrackerHandler(@NonNull com.pubmatic.sdk.common.network.g gVar) {
        if (g == null) {
            synchronized (n.class) {
                try {
                    if (g == null) {
                        g = new n(gVar);
                    }
                } finally {
                }
            }
        }
        return g;
    }
}
