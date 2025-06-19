package com.onetrust.otpublishers.headless.UI.TVUI.datautils;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import androidx.browser.customtabs.k;
import androidx.camera.camera2.internal.a0;
import androidx.compose.ui.node.V;
import androidx.constraintlayout.motion.widget.n;
import androidx.navigation.internal.m;
import com.comscore.streaming.ContentType;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.datatransport.runtime.q;
import com.google.android.gms.internal.ads.B;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.measurement.internal.Z;
import com.google.firebase.crashlytics.internal.common.h;
import com.google.firebase.crashlytics.internal.common.r;
import com.google.firebase.crashlytics.internal.common.u;
import com.google.firebase.crashlytics.internal.common.v;
import com.google.firebase.crashlytics.internal.metadata.f;
import com.google.firebase.crashlytics.internal.metadata.o;
import com.google.firebase.crashlytics.internal.metadata.p;
import com.google.firebase.crashlytics.internal.model.A;
import com.google.firebase.crashlytics.internal.model.C3925a0;
import com.google.firebase.crashlytics.internal.model.C3931d0;
import com.google.firebase.crashlytics.internal.model.C3933e0;
import com.google.firebase.crashlytics.internal.model.C3937g0;
import com.google.firebase.crashlytics.internal.model.C3939h0;
import com.google.firebase.crashlytics.internal.model.D0;
import com.google.firebase.crashlytics.internal.model.F;
import com.google.firebase.crashlytics.internal.model.K0;
import com.google.firebase.crashlytics.internal.model.O;
import com.google.firebase.crashlytics.internal.model.P;
import com.google.firebase.crashlytics.internal.model.Q;
import com.google.firebase.crashlytics.internal.model.S;
import com.google.firebase.crashlytics.internal.model.U;
import com.google.firebase.crashlytics.internal.model.W;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigClientException;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigServerException;
import com.onetrust.otpublishers.headless.UI.UIProperty.g;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Stack;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicMarkableReference;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class d {
    public static d h;
    public Object a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;
    public Object g;

    public d() {
        this.a = new AtomicBoolean();
        this.b = null;
        this.c = new HashMap(16, 1.0f);
        this.d = new HashMap(16, 1.0f);
        this.e = new HashMap(16, 1.0f);
        this.f = new HashMap(16, 1.0f);
        this.g = null;
    }

    public static synchronized d a() {
        try {
            if (h == null) {
                d dVar = new d();
                dVar.e = "";
                h = dVar;
            }
        } catch (Throwable th) {
            throw th;
        }
        return h;
    }

    public static void b(int i, JSONArray jSONArray, JSONArray jSONArray2, JSONObject jSONObject) throws JSONException {
        if (!jSONArray.getJSONObject(i).has("ShowSDKListLink") || jSONArray.getJSONObject(i).getBoolean("ShowSDKListLink")) {
            if (jSONArray.getJSONObject(i).getString("Type").equals("COOKIE") && jSONArray.getJSONObject(i).getJSONArray("FirstPartyCookies").length() > 0) {
                JSONObject jSONObject2 = jSONArray.getJSONObject(i);
                String strOptString = jSONObject2.optString("GroupNameMobile");
                if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                    strOptString = jSONObject2.optString("GroupName");
                }
                jSONObject.put("GroupName", strOptString);
                jSONObject.put("CustomGroupId", jSONArray.getJSONObject(i).optString("CustomGroupId", ""));
                jSONArray2.put(jSONObject);
            }
            if (jSONArray.getJSONObject(i).has("SubGroups")) {
                JSONArray jSONArray3 = jSONArray.getJSONObject(i).getJSONArray("SubGroups");
                for (int i2 = 0; i2 < jSONArray3.length(); i2++) {
                    JSONObject jSONObject3 = new JSONObject();
                    if (jSONArray3.getJSONObject(i2).getString("Type").equals("COOKIE") && jSONArray3.getJSONObject(i2).getJSONArray("FirstPartyCookies").length() > 0) {
                        JSONObject jSONObject4 = jSONArray3.getJSONObject(i2);
                        String strOptString2 = jSONObject4.optString("GroupNameMobile");
                        if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString2)) {
                            strOptString2 = jSONObject4.optString("GroupName");
                        }
                        jSONObject3.put("GroupName", strOptString2);
                        jSONObject3.put("CustomGroupId", jSONArray3.getJSONObject(i2).optString("CustomGroupId", ""));
                        jSONArray2.put(jSONObject3);
                    }
                }
            }
        }
    }

    public static P d(P p, f fVar, d dVar, Map map) {
        Map mapUnmodifiableMap;
        Map mapUnmodifiableMap2;
        Map mapUnmodifiableMap3;
        O oA = p.a();
        String strF = ((com.google.firebase.crashlytics.internal.metadata.d) fVar.b).f();
        if (strF != null) {
            oA.e = new C3931d0(strF);
        } else {
            Log.isLoggable("FirebaseCrashlytics", 2);
        }
        boolean zIsEmpty = map.isEmpty();
        k kVar = (k) dVar.d;
        if (zIsEmpty) {
            com.google.firebase.crashlytics.internal.metadata.e eVar = (com.google.firebase.crashlytics.internal.metadata.e) ((AtomicMarkableReference) kVar.b).getReference();
            synchronized (eVar) {
                mapUnmodifiableMap2 = Collections.unmodifiableMap(new HashMap(eVar.a));
            }
        } else {
            com.google.firebase.crashlytics.internal.metadata.e eVar2 = (com.google.firebase.crashlytics.internal.metadata.e) ((AtomicMarkableReference) kVar.b).getReference();
            synchronized (eVar2) {
                mapUnmodifiableMap = Collections.unmodifiableMap(new HashMap(eVar2.a));
            }
            HashMap map2 = new HashMap(mapUnmodifiableMap);
            int i = 0;
            for (Map.Entry entry : map.entrySet()) {
                String strA = com.google.firebase.crashlytics.internal.metadata.e.a(1024, (String) entry.getKey());
                if (map2.size() < 64 || map2.containsKey(strA)) {
                    map2.put(strA, com.google.firebase.crashlytics.internal.metadata.e.a(1024, (String) entry.getValue()));
                } else {
                    i++;
                }
            }
            if (i > 0) {
                Log.w("FirebaseCrashlytics", "Ignored " + i + " keys when adding event specific keys. Maximum allowable: 1024", null);
            }
            mapUnmodifiableMap2 = Collections.unmodifiableMap(map2);
        }
        List listI = i(mapUnmodifiableMap2);
        com.google.firebase.crashlytics.internal.metadata.e eVar3 = (com.google.firebase.crashlytics.internal.metadata.e) ((AtomicMarkableReference) ((k) dVar.e).b).getReference();
        synchronized (eVar3) {
            mapUnmodifiableMap3 = Collections.unmodifiableMap(new HashMap(eVar3.a));
        }
        List listI2 = i(mapUnmodifiableMap3);
        if (!listI.isEmpty() || !listI2.isEmpty()) {
            Q q = p.c;
            oA.c = new Q(q.a, listI, listI2, q.d, q.e, q.f, q.g);
        }
        return oA.a();
    }

    public static K0 e(P p, d dVar) {
        List listB = ((p) dVar.f).b();
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < listB.size(); i++) {
            o oVar = (o) listB.get(i);
            oVar.getClass();
            C3933e0 c3933e0 = new C3933e0();
            com.google.firebase.crashlytics.internal.metadata.b bVar = (com.google.firebase.crashlytics.internal.metadata.b) oVar;
            String str = bVar.e;
            if (str == null) {
                throw new NullPointerException("Null variantId");
            }
            String str2 = bVar.b;
            if (str2 == null) {
                throw new NullPointerException("Null rolloutId");
            }
            c3933e0.a = new C3937g0(str2, str);
            String str3 = bVar.c;
            if (str3 == null) {
                throw new NullPointerException("Null parameterKey");
            }
            c3933e0.b = str3;
            String str4 = bVar.d;
            if (str4 == null) {
                throw new NullPointerException("Null parameterValue");
            }
            c3933e0.c = str4;
            c3933e0.d = bVar.f;
            c3933e0.e = (byte) (c3933e0.e | 1);
            arrayList.add(c3933e0.a());
        }
        if (arrayList.isEmpty()) {
            return p;
        }
        O oA = p.a();
        oA.f = new C3939h0(arrayList);
        return oA.a();
    }

    public static String g(InputStream inputStream) throws IOException {
        BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            try {
                byte[] bArr = new byte[8192];
                while (true) {
                    int i = bufferedInputStream.read(bArr);
                    if (i == -1) {
                        String string = byteArrayOutputStream.toString(StandardCharsets.UTF_8.name());
                        byteArrayOutputStream.close();
                        bufferedInputStream.close();
                        return string;
                    }
                    byteArrayOutputStream.write(bArr, 0, i);
                }
            } finally {
            }
        } catch (Throwable th) {
            try {
                bufferedInputStream.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    public static d h(Context context, v vVar, com.google.firebase.crashlytics.internal.persistence.c cVar, V v, f fVar, d dVar, com.quizlet.data.repository.searchexplanations.c cVar2, s sVar, com.quizlet.data.repository.explanations.myexplanations.a aVar, h hVar, com.google.firebase.crashlytics.internal.concurrency.d dVar2) {
        r rVar = new r(context, vVar, v, cVar2, sVar);
        com.google.firebase.crashlytics.internal.persistence.a aVar2 = new com.google.firebase.crashlytics.internal.persistence.a(cVar, sVar, hVar);
        com.google.firebase.crashlytics.internal.model.serialization.a aVar3 = com.google.firebase.crashlytics.internal.send.a.b;
        q.b(context);
        com.google.firebase.crashlytics.internal.send.a aVar4 = new com.google.firebase.crashlytics.internal.send.a(new com.google.firebase.crashlytics.internal.send.c(q.a().c(new com.google.android.datatransport.cct.a(com.google.firebase.crashlytics.internal.send.a.c, com.google.firebase.crashlytics.internal.send.a.d)).a("FIREBASE_CRASHLYTICS_REPORT", new com.google.android.datatransport.c("json"), com.google.firebase.crashlytics.internal.send.a.e), sVar.l(), aVar));
        d dVar3 = new d();
        dVar3.a = rVar;
        dVar3.b = aVar2;
        dVar3.c = aVar4;
        dVar3.d = fVar;
        dVar3.e = dVar;
        dVar3.f = vVar;
        dVar3.g = dVar2;
        return dVar3;
    }

    public static List i(Map map) {
        ArrayList arrayList = new ArrayList();
        arrayList.ensureCapacity(map.size());
        for (Map.Entry entry : map.entrySet()) {
            String str = (String) entry.getKey();
            if (str == null) {
                throw new NullPointerException("Null key");
            }
            String str2 = (String) entry.getValue();
            if (str2 == null) {
                throw new NullPointerException("Null value");
            }
            arrayList.add(new F(str, str2));
        }
        Collections.sort(arrayList, new a0(15));
        return Collections.unmodifiableList(arrayList);
    }

    public void c(Context context) throws JSONException {
        boolean z;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        n nVar;
        try {
            JSONObject jSONObject = (JSONObject) this.a;
            int i = 0;
            if (jSONObject == null) {
                SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                if (AbstractC3605e0.a(new com.onetrust.otpublishers.headless.Internal.Preferences.d(context, "OTT_DEFAULT_USER").b().getString("OT_ENABLE_MULTI_PROFILE", Boolean.FALSE.toString()))) {
                    fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                    z = true;
                } else {
                    z = false;
                    fVar = null;
                }
                if (z) {
                    sharedPreferences = fVar;
                }
                String string = sharedPreferences.getString("OTT_PC_DATA", null);
                jSONObject = !com.onetrust.otpublishers.headless.Internal.a.j(string) ? new JSONObject(string) : null;
            }
            this.a = jSONObject;
            if (jSONObject == null) {
                return;
            }
            this.b = jSONObject.optString("PcTextColor");
            if (((JSONObject) this.a).has("LegIntSettings") && !com.onetrust.otpublishers.headless.Internal.a.j("LegIntSettings")) {
                ((JSONObject) this.a).getJSONObject("LegIntSettings").getBoolean("PAllowLI");
            }
            String strOptString = ((JSONObject) this.a).optString("PCenterVendorsListText");
            this.c = ((JSONObject) this.a).optString("PCenterApplyFiltersText");
            this.d = ((JSONObject) this.a).optString("PCenterClearFiltersText");
            this.e = ((JSONObject) this.a).optString("ThirdPartyCookieListText");
            g gVarK = new com.onetrust.otpublishers.headless.UI.UIProperty.d(context).k(22);
            this.f = gVarK;
            if (gVarK != null) {
                if (com.onetrust.otpublishers.headless.Internal.a.j((String) ((m) gVarK.r.b).g)) {
                    ((m) ((g) this.f).r.b).g = strOptString;
                }
                this.g = new n();
                if (b.a().r) {
                    nVar = (n) this.g;
                } else {
                    nVar = (n) this.g;
                    i = 8;
                }
                nVar.b = i;
                if (com.onetrust.otpublishers.headless.Internal.a.j(((g) this.f).f)) {
                    ((g) this.f).f = ((JSONObject) this.a).optString("PcButtonColor");
                }
                n nVar2 = (n) this.g;
                g gVar = (g) this.f;
                nVar2.f = gVar.f;
                if (com.onetrust.otpublishers.headless.Internal.a.j(gVar.g)) {
                    ((g) this.f).g = ((JSONObject) this.a).optString("PcTextColor");
                }
                n nVar3 = (n) this.g;
                nVar3.e = ((g) this.f).g;
                nVar3.l = b.a().g;
            }
        } catch (JSONException e) {
            Z.p("Error while parsing PC data for VL rendering, error: ", e, "OneTrust", 6);
        }
    }

    public void f(int i, long j) {
        if (i == 0) {
            new FirebaseRemoteConfigServerException("Unable to fetch the latest version of the template.");
            m();
            return;
        }
        ((ScheduledExecutorService) this.f).schedule(new B(i, 1, j, this), ((Random) this.g).nextInt(4), TimeUnit.SECONDS);
    }

    public void j(InputStream inputStream) throws JSONException, IOException {
        JSONObject jSONObject;
        boolean zIsEmpty;
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream, "utf-8"));
        String strK = "";
        while (true) {
            String line = bufferedReader.readLine();
            if (line == null) {
                break;
            }
            strK = android.support.v4.media.session.a.k(strK, line);
            if (line.contains("}")) {
                int iIndexOf = strK.indexOf(ContentType.USER_GENERATED_LIVE);
                int iLastIndexOf = strK.lastIndexOf(125);
                strK = (iIndexOf < 0 || iLastIndexOf < 0 || iIndexOf >= iLastIndexOf) ? "" : strK.substring(iIndexOf, iLastIndexOf + 1);
                if (!strK.isEmpty()) {
                    try {
                        jSONObject = new JSONObject(strK);
                    } catch (JSONException e) {
                        new FirebaseRemoteConfigClientException("Unable to parse config update message.", e.getCause());
                        m();
                        Log.e("FirebaseRemoteConfig", "Unable to parse latest config update message.", e);
                    }
                    if (jSONObject.has("featureDisabled") && jSONObject.getBoolean("featureDisabled")) {
                        com.google.firebase.remoteconfig.internal.g gVar = (com.google.firebase.remoteconfig.internal.g) this.e;
                        new FirebaseRemoteConfigServerException("The server is temporarily unavailable. Try again in a few minutes.");
                        gVar.a();
                        break;
                    }
                    synchronized (this) {
                        zIsEmpty = ((LinkedHashSet) this.a).isEmpty();
                    }
                    if (zIsEmpty) {
                        break;
                    }
                    if (jSONObject.has("latestTemplateVersionNumber")) {
                        long j = ((com.google.firebase.remoteconfig.internal.e) this.c).g.a.getLong("last_template_version", 0L);
                        long j2 = jSONObject.getLong("latestTemplateVersionNumber");
                        if (j2 > j) {
                            f(3, j2);
                        }
                    }
                    strK = "";
                } else {
                    continue;
                }
            }
        }
        bufferedReader.close();
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x01c4 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object k(java.lang.String r27, java.lang.String r28, long r29, boolean r31, kotlin.coroutines.jvm.internal.c r32) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 453
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.datautils.d.k(java.lang.String, java.lang.String, long, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void l(Throwable th, Thread thread, String str, final com.google.firebase.crashlytics.internal.metadata.c cVar, boolean z) {
        com.quizlet.data.repository.searchexplanations.c cVar2;
        Iterator<Map.Entry<Thread, StackTraceElement[]>> it2;
        com.quizlet.data.repository.searchexplanations.c cVar3;
        final boolean zEquals = str.equals("crash");
        r rVar = (r) this.a;
        Context context = rVar.a;
        int i = context.getResources().getConfiguration().orientation;
        Stack stack = new Stack();
        for (Throwable cause = th; cause != null; cause = cause.getCause()) {
            stack.push(cause);
        }
        com.quizlet.data.repository.classmembership.c cVar4 = null;
        while (true) {
            boolean zIsEmpty = stack.isEmpty();
            cVar2 = rVar.d;
            if (zIsEmpty) {
                break;
            }
            Throwable th2 = (Throwable) stack.pop();
            cVar4 = new com.quizlet.data.repository.classmembership.c(th2.getLocalizedMessage(), th2.getClass().getName(), cVar2.e(th2.getStackTrace()), cVar4);
        }
        O o = new O();
        o.b = str;
        o.a = cVar.b;
        o.g = (byte) (o.g | 1);
        D0 d0C = com.google.firebase.crashlytics.internal.d.a.c(context);
        int i2 = ((C3925a0) d0C).c;
        Boolean boolValueOf = i2 > 0 ? Boolean.valueOf(i2 != 100) : null;
        ArrayList arrayListB = com.google.firebase.crashlytics.internal.d.b(context);
        byte b = (byte) 1;
        ArrayList arrayList = new ArrayList();
        StackTraceElement[] stackTraceElementArr = (StackTraceElement[]) cVar4.c;
        String name = thread.getName();
        Boolean bool = boolValueOf;
        if (name == null) {
            throw new NullPointerException("Null name");
        }
        byte b2 = (byte) 1;
        List listD = r.d(stackTraceElementArr, 4);
        if (listD == null) {
            throw new NullPointerException("Null frames");
        }
        if (b2 != 1) {
            StringBuilder sb = new StringBuilder();
            if (b2 == 0) {
                sb.append(" importance");
            }
            throw new IllegalStateException(Z.i("Missing required properties:", sb));
        }
        arrayList.add(new W(name, listD, 4));
        if (z) {
            Iterator<Map.Entry<Thread, StackTraceElement[]>> it3 = Thread.getAllStackTraces().entrySet().iterator();
            while (it3.hasNext()) {
                Map.Entry<Thread, StackTraceElement[]> next = it3.next();
                Thread key = next.getKey();
                if (key.equals(thread)) {
                    it2 = it3;
                    cVar3 = cVar2;
                } else {
                    StackTraceElement[] stackTraceElementArrE = cVar2.e(next.getValue());
                    String name2 = key.getName();
                    if (name2 == null) {
                        throw new NullPointerException("Null name");
                    }
                    it2 = it3;
                    List listD2 = r.d(stackTraceElementArrE, 0);
                    if (listD2 == null) {
                        throw new NullPointerException("Null frames");
                    }
                    if (b2 != 1) {
                        StringBuilder sb2 = new StringBuilder();
                        if (b2 == 0) {
                            sb2.append(" importance");
                        }
                        throw new IllegalStateException(Z.i("Missing required properties:", sb2));
                    }
                    cVar3 = cVar2;
                    arrayList.add(new W(name2, listD2, 0));
                }
                it3 = it2;
                cVar2 = cVar3;
            }
        }
        List listUnmodifiableList = Collections.unmodifiableList(arrayList);
        U uC = r.c(cVar4, 0);
        com.google.firebase.crashlytics.internal.model.V vE = r.e();
        List listA = rVar.a();
        if (listA == null) {
            throw new NullPointerException("Null binaries");
        }
        S s = new S(listUnmodifiableList, uC, null, vE, listA);
        if (b != 1) {
            StringBuilder sb3 = new StringBuilder();
            if (b == 0) {
                sb3.append(" uiOrientation");
            }
            throw new IllegalStateException(Z.i("Missing required properties:", sb3));
        }
        o.c = new Q(s, null, null, bool, d0C, arrayListB, i);
        o.d = rVar.b(i);
        P pA = o.a();
        f fVar = (f) this.d;
        d dVar = (d) this.e;
        final K0 k0E = e(d(pA, fVar, dVar, cVar.c), dVar);
        if (z) {
            ((com.google.firebase.crashlytics.internal.persistence.a) this.b).d(k0E, cVar.a, zEquals);
        } else {
            ((com.google.firebase.crashlytics.internal.concurrency.d) this.g).b.a(new Runnable() { // from class: com.google.firebase.crashlytics.internal.common.w
                @Override // java.lang.Runnable
                public final void run() {
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar2 = this.a;
                    dVar2.getClass();
                    Log.isLoggable("FirebaseCrashlytics", 3);
                    ((com.google.firebase.crashlytics.internal.persistence.a) dVar2.b).d(k0E, cVar.a, zEquals);
                }
            });
        }
    }

    public synchronized void m() {
        Iterator it2 = ((LinkedHashSet) this.a).iterator();
        while (it2.hasNext()) {
            ((com.google.firebase.remoteconfig.internal.g) it2.next()).a();
        }
    }

    public com.google.android.gms.tasks.m n(String str, Executor executor) {
        com.google.firebase.crashlytics.internal.common.a aVar;
        com.google.android.gms.tasks.f fVar;
        ArrayList arrayListB = ((com.google.firebase.crashlytics.internal.persistence.a) this.b).b();
        ArrayList arrayList = new ArrayList();
        Iterator it2 = arrayListB.iterator();
        while (it2.hasNext()) {
            File file = (File) it2.next();
            try {
                com.google.firebase.crashlytics.internal.model.serialization.a aVar2 = com.google.firebase.crashlytics.internal.persistence.a.g;
                String strE = com.google.firebase.crashlytics.internal.persistence.a.e(file);
                aVar2.getClass();
                arrayList.add(new com.google.firebase.crashlytics.internal.common.a(com.google.firebase.crashlytics.internal.model.serialization.a.i(strE), file.getName(), file));
            } catch (IOException e) {
                Log.w("FirebaseCrashlytics", "Could not load report file " + file + "; deleting", e);
                file.delete();
            }
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            com.google.firebase.crashlytics.internal.common.a aVar3 = (com.google.firebase.crashlytics.internal.common.a) it3.next();
            if (str == null || str.equals(aVar3.b)) {
                com.google.firebase.crashlytics.internal.send.a aVar4 = (com.google.firebase.crashlytics.internal.send.a) this.c;
                com.google.firebase.crashlytics.internal.model.B b = aVar3.a;
                boolean z = true;
                if (b.f == null || b.g == null) {
                    u uVarB = ((v) this.f).b(true);
                    A a = aVar3.a.a();
                    a.e = uVarB.a;
                    A a2 = a.a().a();
                    a2.f = uVarB.b;
                    aVar = new com.google.firebase.crashlytics.internal.common.a(a2.a(), aVar3.b, aVar3.c);
                } else {
                    aVar = aVar3;
                }
                boolean z2 = str != null;
                com.google.firebase.crashlytics.internal.send.c cVar = aVar4.a;
                synchronized (cVar.f) {
                    try {
                        fVar = new com.google.android.gms.tasks.f();
                        if (z2) {
                            ((AtomicInteger) cVar.i.b).getAndIncrement();
                            if (cVar.f.size() >= cVar.e) {
                                z = false;
                            }
                            if (z) {
                                Log.isLoggable("FirebaseCrashlytics", 3);
                                cVar.f.size();
                                Log.isLoggable("FirebaseCrashlytics", 3);
                                cVar.g.execute(new androidx.core.provider.k(22, cVar, aVar, fVar, false));
                                Log.isLoggable("FirebaseCrashlytics", 3);
                                fVar.d(aVar);
                            } else {
                                cVar.a();
                                Log.isLoggable("FirebaseCrashlytics", 3);
                                ((AtomicInteger) cVar.i.c).getAndIncrement();
                                fVar.d(aVar);
                            }
                        } else {
                            cVar.b(aVar, fVar);
                        }
                    } finally {
                    }
                }
                arrayList2.add(fVar.a.e(executor, new com.google.android.material.search.a(this, 6)));
            }
        }
        return S3.j(arrayList2);
    }

    public d(String str, com.google.firebase.crashlytics.internal.persistence.c cVar, com.google.firebase.crashlytics.internal.concurrency.d dVar) {
        this.d = new k(this, false);
        this.e = new k(this, true);
        this.f = new p(0);
        this.g = new AtomicMarkableReference(null, false);
        this.b = str;
        this.a = new com.google.firebase.crashlytics.internal.metadata.h(cVar);
        this.c = dVar;
    }
}
