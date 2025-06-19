package com.google.firebase.remoteconfig;

import android.util.Log;
import com.facebook.login.E;
import com.google.firebase.remoteconfig.internal.h;
import com.google.firebase.remoteconfig.internal.j;
import com.google.firebase.remoteconfig.internal.l;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.concurrent.Executor;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class b {
    public final com.google.firebase.abt.b a;
    public final Executor b;
    public final com.google.firebase.remoteconfig.internal.b c;
    public final com.google.firebase.remoteconfig.internal.b d;
    public final com.google.firebase.remoteconfig.internal.e e;
    public final com.google.firebase.remoteconfig.internal.f f;
    public final j g;
    public final com.quizlet.data.repository.classfolder.e h;
    public final com.quizlet.data.repository.explanations.question.a i;

    public b(com.google.firebase.abt.b bVar, Executor executor, com.google.firebase.remoteconfig.internal.b bVar2, com.google.firebase.remoteconfig.internal.b bVar3, com.google.firebase.remoteconfig.internal.b bVar4, com.google.firebase.remoteconfig.internal.e eVar, com.google.firebase.remoteconfig.internal.f fVar, j jVar, com.quizlet.data.repository.classfolder.e eVar2, com.quizlet.data.repository.explanations.question.a aVar) {
        this.a = bVar;
        this.b = executor;
        this.c = bVar2;
        this.d = bVar3;
        this.e = eVar;
        this.f = fVar;
        this.g = jVar;
        this.h = eVar2;
        this.i = aVar;
    }

    public static ArrayList d(JSONArray jSONArray) throws JSONException {
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < jSONArray.length(); i++) {
            HashMap map = new HashMap();
            JSONObject jSONObject = jSONArray.getJSONObject(i);
            Iterator<String> itKeys = jSONObject.keys();
            while (itKeys.hasNext()) {
                String next = itKeys.next();
                map.put(next, jSONObject.getString(next));
            }
            arrayList.add(map);
        }
        return arrayList;
    }

    public final HashMap a() throws JSONException {
        String string;
        l lVar;
        com.google.firebase.remoteconfig.internal.f fVar = this.f;
        HashSet hashSet = new HashSet();
        hashSet.addAll(com.google.firebase.remoteconfig.internal.f.a(fVar.c));
        hashSet.addAll(com.google.firebase.remoteconfig.internal.f.a(fVar.d));
        HashMap map = new HashMap();
        Iterator it2 = hashSet.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            com.google.firebase.remoteconfig.internal.c cVarC = fVar.c.c();
            String string2 = null;
            if (cVarC == null) {
                string = null;
            } else {
                try {
                    string = cVarC.b.getString(str);
                } catch (JSONException unused) {
                }
            }
            if (string != null) {
                com.google.firebase.remoteconfig.internal.c cVarC2 = fVar.c.c();
                if (cVarC2 != null) {
                    synchronized (fVar.a) {
                        try {
                            Iterator it3 = fVar.a.iterator();
                            while (it3.hasNext()) {
                                fVar.b.execute(new E((d) it3.next(), str, cVarC2, 7));
                            }
                        } catch (Throwable th) {
                            throw th;
                        }
                    }
                }
                lVar = new l(string, 2);
            } else {
                com.google.firebase.remoteconfig.internal.c cVarC3 = fVar.d.c();
                if (cVarC3 != null) {
                    try {
                        string2 = cVarC3.b.getString(str);
                    } catch (JSONException unused2) {
                    }
                }
                if (string2 != null) {
                    lVar = new l(string2, 1);
                } else {
                    Log.w("FirebaseRemoteConfig", "No value of type 'FirebaseRemoteConfigValue' exists for parameter key '" + str + "'.");
                    lVar = new l("", 0);
                }
            }
            map.put(str, lVar);
        }
        return map;
    }

    public final com.airbnb.lottie.parser.l b() {
        com.airbnb.lottie.parser.l lVar;
        j jVar = this.g;
        synchronized (jVar.b) {
            try {
                jVar.a.getLong("last_fetch_time_in_millis", -1L);
                int i = jVar.a.getInt("last_fetch_status", 0);
                long j = com.google.firebase.remoteconfig.internal.e.i;
                long j2 = jVar.a.getLong("fetch_timeout_in_seconds", 60L);
                if (j2 < 0) {
                    throw new IllegalArgumentException(String.format("Fetch connection timeout has to be a non-negative number. %d is an invalid argument", Long.valueOf(j2)));
                }
                long j3 = jVar.a.getLong("minimum_fetch_interval_in_seconds", j);
                if (j3 < 0) {
                    throw new IllegalArgumentException("Minimum interval between fetches has to be a non-negative number. " + j3 + " is an invalid argument");
                }
                lVar = new com.airbnb.lottie.parser.l(i, 12);
            } catch (Throwable th) {
                throw th;
            }
        }
        return lVar;
    }

    public final void c(boolean z) {
        HttpURLConnection httpURLConnection;
        com.quizlet.data.repository.classfolder.e eVar = this.h;
        synchronized (eVar) {
            h hVar = (h) eVar.c;
            synchronized (hVar.q) {
                try {
                    hVar.e = z;
                    if (z && (httpURLConnection = hVar.f) != null) {
                        httpURLConnection.disconnect();
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
            if (!z) {
                synchronized (eVar) {
                    if (!((LinkedHashSet) eVar.b).isEmpty()) {
                        ((h) eVar.c).e(0L);
                    }
                }
            }
        }
    }
}
