package com.google.firebase.remoteconfig.internal;

import android.text.format.DateUtils;
import androidx.camera.camera2.internal.C0143u;
import androidx.work.H;
import com.google.android.gms.internal.measurement.C3008j0;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.m;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigClientException;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigException;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigFetchThrottledException;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigServerException;
import java.net.HttpURLConnection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class e {
    public static final long i = TimeUnit.HOURS.toSeconds(12);
    public static final int[] j = {2, 4, 8, 16, 32, 64, 128, 256};
    public final com.google.firebase.installations.d a;
    public final com.google.firebase.inject.b b;
    public final Executor c;
    public final Random d;
    public final b e;
    public final ConfigFetchHttpClient f;
    public final j g;
    public final HashMap h;

    public e(com.google.firebase.installations.d dVar, com.google.firebase.inject.b bVar, Executor executor, Random random, b bVar2, ConfigFetchHttpClient configFetchHttpClient, j jVar, HashMap map) {
        this.a = dVar;
        this.b = bVar;
        this.c = executor;
        this.d = random;
        this.e = bVar2;
        this.f = configFetchHttpClient;
        this.g = jVar;
        this.h = map;
    }

    public final d a(String str, String str2, Date date, HashMap map) throws FirebaseRemoteConfigException {
        String str3;
        try {
            HttpURLConnection httpURLConnectionB = this.f.b();
            ConfigFetchHttpClient configFetchHttpClient = this.f;
            HashMap mapD = d();
            String string = this.g.a.getString("last_fetch_etag", null);
            com.google.firebase.analytics.connector.b bVar = (com.google.firebase.analytics.connector.b) this.b.get();
            d dVarFetch = configFetchHttpClient.fetch(httpURLConnectionB, str, str2, mapD, string, map, bVar != null ? (Long) ((C3008j0) ((com.google.firebase.analytics.connector.c) bVar).a.a).h(null, null, true).get("_fot") : null, date, this.g.b());
            c cVar = dVarFetch.b;
            if (cVar != null) {
                j jVar = this.g;
                long j2 = cVar.f;
                synchronized (jVar.b) {
                    jVar.a.edit().putLong("last_template_version", j2).apply();
                }
            }
            String str4 = dVarFetch.c;
            if (str4 != null) {
                j jVar2 = this.g;
                synchronized (jVar2.b) {
                    jVar2.a.edit().putString("last_fetch_etag", str4).apply();
                }
            }
            this.g.d(0, j.f);
            return dVarFetch;
        } catch (FirebaseRemoteConfigServerException e) {
            int i2 = e.a;
            j jVar3 = this.g;
            if (i2 == 429 || i2 == 502 || i2 == 503 || i2 == 504) {
                int i3 = jVar3.a().a + 1;
                TimeUnit timeUnit = TimeUnit.MINUTES;
                int[] iArr = j;
                jVar3.d(i3, new Date(date.getTime() + (timeUnit.toMillis(iArr[Math.min(i3, iArr.length) - 1]) / 2) + this.d.nextInt((int) r3)));
            }
            i iVarA = jVar3.a();
            int i4 = e.a;
            if (iVarA.a > 1 || i4 == 429) {
                iVarA.b.getTime();
                throw new FirebaseRemoteConfigFetchThrottledException("Fetch was throttled.");
            }
            if (i4 == 401) {
                str3 = "The request did not have the required credentials. Please make sure your google-services.json is valid.";
            } else if (i4 == 403) {
                str3 = "The user is not authorized to access the project. Please make sure you are using the API key that corresponds to your Firebase project.";
            } else {
                if (i4 == 429) {
                    throw new FirebaseRemoteConfigClientException("The throttled response from the server was not handled correctly by the FRC SDK.");
                }
                if (i4 != 500) {
                    switch (i4) {
                        case 502:
                        case 503:
                        case 504:
                            str3 = "The server is unavailable. Please try again later.";
                            break;
                        default:
                            str3 = "The server returned an unexpected error.";
                            break;
                    }
                } else {
                    str3 = "There was an internal server error.";
                }
            }
            throw new FirebaseRemoteConfigServerException(e.a, "Fetch failed: ".concat(str3), e);
        }
    }

    public final Task b(Task task, long j2, HashMap map) {
        Task taskF;
        Date date = new Date(System.currentTimeMillis());
        boolean zL = task.l();
        j jVar = this.g;
        if (zL) {
            Date date2 = new Date(jVar.a.getLong("last_fetch_time_in_millis", -1L));
            if (date2.equals(j.e) ? false : date.before(new Date(TimeUnit.SECONDS.toMillis(j2) + date2.getTime()))) {
                return S3.i(new d(2, null, null));
            }
        }
        Date date3 = jVar.a().b;
        Date date4 = date.before(date3) ? date3 : null;
        Executor executor = this.c;
        if (date4 != null) {
            String str = "Fetch is throttled. Please wait before calling fetch again: " + DateUtils.formatElapsedTime(TimeUnit.MILLISECONDS.toSeconds(date4.getTime() - date.getTime()));
            date4.getTime();
            taskF = S3.h(new FirebaseRemoteConfigFetchThrottledException(str));
        } else {
            com.google.firebase.installations.c cVar = (com.google.firebase.installations.c) this.a;
            m mVarC = cVar.c();
            m mVarD = cVar.d();
            taskF = S3.k(mVarC, mVarD).f(executor, new H(this, mVarC, mVarD, date, map));
        }
        return taskF.f(executor, new C0143u(27, this, date));
    }

    public final Task c(int i2) {
        HashMap map = new HashMap(this.h);
        map.put("X-Firebase-RC-Fetch-Type", "REALTIME/" + i2);
        return this.e.b().f(this.c, new C0143u(28, this, map));
    }

    public final HashMap d() {
        HashMap map = new HashMap();
        com.google.firebase.analytics.connector.b bVar = (com.google.firebase.analytics.connector.b) this.b.get();
        if (bVar != null) {
            for (Map.Entry entry : ((C3008j0) ((com.google.firebase.analytics.connector.c) bVar).a.a).h(null, null, false).entrySet()) {
                map.put((String) entry.getKey(), entry.getValue().toString());
            }
        }
        return map;
    }
}
