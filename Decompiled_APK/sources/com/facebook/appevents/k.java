package com.facebook.appevents;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Base64;
import android.util.Log;
import androidx.camera.camera2.internal.RunnableC0131h;
import androidx.camera.camera2.internal.a0;
import androidx.camera.camera2.internal.c0;
import com.facebook.B;
import com.facebook.internal.A;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.C1563s;
import com.facebook.internal.EnumC1562q;
import com.facebook.internal.H;
import com.facebook.internal.InterfaceC1561p;
import com.facebook.internal.J;
import com.facebook.internal.y;
import com.facebook.x;
import com.google.android.gms.internal.mlkit_vision_common.E2;
import com.google.android.gms.internal.mlkit_vision_common.F2;
import com.google.android.gms.internal.mlkit_vision_common.G2;
import com.google.firebase.abt.component.AbtRegistrar;
import com.google.firebase.components.ComponentRegistrar;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.C4937f;
import kotlin.collections.F;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final /* synthetic */ class k implements InterfaceC1561p, com.google.android.datatransport.g, com.google.android.datatransport.runtime.scheduling.persistence.e, com.google.android.material.textfield.w, com.google.common.base.l, com.google.firebase.components.d, com.google.firebase.components.e {
    public final /* synthetic */ int a;

    public /* synthetic */ k(int i) {
        this.a = i;
    }

    @Override // com.google.firebase.components.e
    public List a(ComponentRegistrar componentRegistrar) {
        return componentRegistrar.getComponents();
    }

    @Override // com.google.android.datatransport.runtime.scheduling.persistence.e, io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Cursor cursorRawQuery = ((SQLiteDatabase) obj).rawQuery("SELECT distinct t._id, t.backend_name, t.priority, t.extras FROM transport_contexts AS t, events AS e WHERE e.context_id = t._id", new String[0]);
        try {
            ArrayList arrayList = new ArrayList();
            while (cursorRawQuery.moveToNext()) {
                com.quizlet.data.repository.set.f fVarA = com.google.android.datatransport.runtime.i.a();
                fVarA.s(cursorRawQuery.getString(1));
                fVarA.d = com.google.android.datatransport.runtime.util.a.b(cursorRawQuery.getInt(2));
                String string = cursorRawQuery.getString(3);
                fVarA.c = string == null ? null : Base64.decode(string, 0);
                arrayList.add(fVarA.b());
            }
            return arrayList;
        } finally {
            cursorRawQuery.close();
        }
    }

    @Override // com.google.android.datatransport.g
    public void b(Exception exc) {
    }

    @Override // com.facebook.internal.InterfaceC1561p
    public void c(boolean z) throws JSONException {
        HashSet hashSetF;
        File[] fileArrListFiles;
        File[] fileArrListFiles2;
        int i = 13;
        int i2 = 1;
        switch (this.a) {
            case 0:
                if (z) {
                    com.facebook.appevents.integrity.f fVar = com.facebook.appevents.integrity.f.a;
                    if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.integrity.f.class)) {
                        return;
                    }
                    try {
                        com.facebook.appevents.integrity.f.b = true;
                        com.facebook.appevents.integrity.f.a.a();
                        return;
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.integrity.f.class, th);
                        return;
                    }
                }
                return;
            case 1:
                if (!z || com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.integrity.d.class)) {
                    return;
                }
                try {
                    com.facebook.appevents.integrity.d dVar = com.facebook.appevents.integrity.d.a;
                    if (!com.facebook.internal.instrument.crashshield.a.b(dVar)) {
                        try {
                            com.facebook.internal.v vVarK = y.k(com.facebook.o.b(), false);
                            if (vVarK != null) {
                                com.facebook.appevents.integrity.d.c = vVarK.n;
                            }
                        } catch (Throwable th2) {
                            com.facebook.internal.instrument.crashshield.a.a(dVar, th2);
                        }
                    }
                    if (com.facebook.appevents.integrity.d.c != null) {
                        com.facebook.appevents.integrity.d.b = true;
                        return;
                    }
                    return;
                } catch (Throwable th3) {
                    com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.integrity.d.class, th3);
                    return;
                }
            case 2:
                if (z) {
                    com.facebook.appevents.integrity.b bVar = com.facebook.appevents.integrity.b.a;
                    if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.integrity.b.class)) {
                        return;
                    }
                    try {
                        com.facebook.appevents.integrity.b bVar2 = com.facebook.appevents.integrity.b.a;
                        if (!com.facebook.internal.instrument.crashshield.a.b(bVar2)) {
                            try {
                                com.facebook.internal.v vVarK2 = y.k(com.facebook.o.b(), false);
                                if (vVarK2 != null && (hashSetF = J.f(vVarK2.o)) != null) {
                                    com.facebook.appevents.integrity.b.c = hashSetF;
                                }
                            } catch (Throwable th4) {
                                com.facebook.internal.instrument.crashshield.a.a(bVar2, th4);
                            }
                        }
                        HashSet hashSet = com.facebook.appevents.integrity.b.c;
                        if (hashSet != null && !hashSet.isEmpty()) {
                            com.facebook.appevents.integrity.b.b = true;
                            return;
                        }
                        return;
                    } catch (Throwable th5) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.integrity.b.class, th5);
                        return;
                    }
                }
                return;
            case 3:
                if (z) {
                    com.facebook.appevents.integrity.g gVar = com.facebook.appevents.integrity.g.a;
                    if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.integrity.g.class)) {
                        return;
                    }
                    try {
                        com.facebook.appevents.integrity.g.a.a();
                        if (com.facebook.appevents.integrity.g.c.isEmpty()) {
                            return;
                        }
                        com.facebook.appevents.integrity.g.b = true;
                        return;
                    } catch (Throwable th6) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.integrity.g.class, th6);
                        return;
                    }
                }
                return;
            case 4:
                if (z) {
                    com.facebook.appevents.integrity.h hVar = com.facebook.appevents.integrity.h.a;
                    if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.integrity.h.class)) {
                        return;
                    }
                    try {
                        com.facebook.appevents.integrity.h.a.a();
                        if (com.facebook.appevents.integrity.h.c.isEmpty() && com.facebook.appevents.integrity.h.d.isEmpty()) {
                            com.facebook.appevents.integrity.h.b = false;
                        } else {
                            com.facebook.appevents.integrity.h.b = true;
                        }
                        return;
                    } catch (Throwable th7) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.integrity.h.class, th7);
                        return;
                    }
                }
                return;
            case 5:
                if (z) {
                    com.facebook.y yVar = com.facebook.y.d;
                    try {
                        com.facebook.t tVar = new com.facebook.t(null, com.facebook.o.b().concat("/cloudbridge_settings"), null, x.a, new com.facebook.r(i2));
                        com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
                        com.google.mlkit.common.sdkinternal.model.a.w(yVar, "com.facebook.appevents.cloudbridge.c", " \n\nCreating Graph Request: \n=============\n%s\n\n ", tVar);
                        tVar.d();
                        return;
                    } catch (JSONException e) {
                        com.google.mlkit.common.sdkinternal.model.a aVar2 = A.c;
                        com.google.mlkit.common.sdkinternal.model.a.w(yVar, "com.facebook.appevents.cloudbridge.c", " \n\nGraph Request Exception: \n=============\n%s\n\n ", C4937f.b(e));
                        return;
                    }
                }
                return;
            case 6:
                if (z) {
                    com.facebook.appevents.gps.ara.c cVar = com.facebook.appevents.gps.ara.c.a;
                    if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.gps.ara.c.class)) {
                        return;
                    }
                    try {
                        com.facebook.appevents.gps.ara.c.c = true;
                        com.facebook.appevents.gps.ara.c.d = new com.facebook.appevents.gps.a(com.facebook.o.a());
                        com.facebook.appevents.gps.ara.c.e = "https://www." + com.facebook.o.q + "/privacy_sandbox/mobile/register/trigger";
                        return;
                    } catch (Throwable th8) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.gps.ara.c.class, th8);
                        return;
                    }
                }
                return;
            case 7:
                if (z) {
                    com.facebook.appevents.gps.pa.b.a();
                    return;
                }
                return;
            case 8:
                if (z) {
                    AtomicBoolean atomicBoolean = com.facebook.appevents.gps.topics.b.a;
                    if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.gps.topics.b.class)) {
                        return;
                    }
                    try {
                        com.facebook.appevents.gps.topics.b.a.set(true);
                        return;
                    } catch (Throwable th9) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.gps.topics.b.class, th9);
                        return;
                    }
                }
                return;
            case 9:
                if (z) {
                    com.facebook.appevents.restrictivedatafilter.b bVar3 = com.facebook.appevents.restrictivedatafilter.b.a;
                    if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.restrictivedatafilter.b.class)) {
                        return;
                    }
                    try {
                        com.facebook.appevents.restrictivedatafilter.b.b = true;
                        com.facebook.appevents.restrictivedatafilter.b.a.b();
                        return;
                    } catch (Throwable th10) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.restrictivedatafilter.b.class, th10);
                        return;
                    }
                }
                return;
            case 10:
                if (z) {
                    com.facebook.appevents.ml.e eVar = com.facebook.appevents.ml.e.a;
                    if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.ml.e.class)) {
                        return;
                    }
                    try {
                        J.M(new RunnableC0131h(i));
                        return;
                    } catch (Throwable th11) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.ml.e.class, th11);
                        return;
                    }
                }
                return;
            case 11:
                if (z) {
                    com.facebook.appevents.eventdeactivation.b bVar4 = com.facebook.appevents.eventdeactivation.b.a;
                    if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.eventdeactivation.b.class)) {
                        return;
                    }
                    try {
                        com.facebook.appevents.eventdeactivation.b.b = true;
                        com.facebook.appevents.eventdeactivation.b.a.a();
                        return;
                    } catch (Throwable th12) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.eventdeactivation.b.class, th12);
                        return;
                    }
                }
                return;
            case 12:
                if (z) {
                    com.facebook.appevents.codeless.d dVar2 = com.facebook.appevents.codeless.d.a;
                    if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.codeless.d.class)) {
                        return;
                    }
                    try {
                        com.facebook.appevents.codeless.d.f.set(true);
                        return;
                    } catch (Throwable th13) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.codeless.d.class, th13);
                        return;
                    }
                }
                com.facebook.appevents.codeless.d dVar3 = com.facebook.appevents.codeless.d.a;
                if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.codeless.d.class)) {
                    return;
                }
                try {
                    com.facebook.appevents.codeless.d.f.set(false);
                    return;
                } catch (Throwable th14) {
                    com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.codeless.d.class, th14);
                    return;
                }
            case 13:
                if (z) {
                    synchronized (com.facebook.internal.instrument.crashreport.a.b) {
                        com.facebook.o oVar = com.facebook.o.a;
                        if (B.c()) {
                            com.onetrust.otpublishers.headless.Internal.Helper.h.w();
                        }
                        if (com.facebook.internal.instrument.crashreport.a.c != null) {
                            Log.w("com.facebook.internal.instrument.crashreport.a", "Already enabled!");
                        } else {
                            com.facebook.internal.instrument.crashreport.a aVar3 = new com.facebook.internal.instrument.crashreport.a(Thread.getDefaultUncaughtExceptionHandler());
                            com.facebook.internal.instrument.crashreport.a.c = aVar3;
                            Thread.setDefaultUncaughtExceptionHandler(aVar3);
                        }
                    }
                    if (C1563s.b(EnumC1562q.CrashShield)) {
                        E2.a = true;
                        if (B.c() && !J.B()) {
                            File fileD = G2.d();
                            if (fileD == null) {
                                fileArrListFiles = new File[0];
                            } else {
                                fileArrListFiles = fileD.listFiles(new H(3));
                                if (fileArrListFiles == null) {
                                    fileArrListFiles = new File[0];
                                }
                            }
                            ArrayList arrayList = new ArrayList();
                            for (File file : fileArrListFiles) {
                                com.facebook.internal.instrument.c cVarD = F2.d(file);
                                if (cVarD.a()) {
                                    JSONObject jSONObject = new JSONObject();
                                    try {
                                        jSONObject.put("crash_shield", cVarD.toString());
                                        String str = com.facebook.t.j;
                                        String str2 = String.format("%s/instruments", Arrays.copyOf(new Object[]{com.facebook.o.b()}, 1));
                                        Intrinsics.checkNotNullExpressionValue(str2, "format(format, *args)");
                                        arrayList.add(assistantMode.utils.studiableMetadata.b.R(null, str2, jSONObject, new com.facebook.c(cVarD, i2)));
                                    } catch (JSONException unused) {
                                    }
                                }
                            }
                            if (!arrayList.isEmpty()) {
                                com.facebook.v requests = new com.facebook.v(arrayList);
                                String str3 = com.facebook.t.j;
                                Intrinsics.checkNotNullParameter(requests, "requests");
                                AbstractC1554i.i(requests);
                                new com.facebook.u(requests).executeOnExecutor(com.facebook.o.c(), new Void[0]);
                            }
                        }
                        com.facebook.internal.instrument.crashshield.a.b = true;
                    }
                    C1563s.b(EnumC1562q.ThreadCheck);
                    return;
                }
                return;
            case 14:
                if (z) {
                    com.facebook.o oVar2 = com.facebook.o.a;
                    if (!B.c() || J.B()) {
                        return;
                    }
                    File fileD2 = G2.d();
                    if (fileD2 == null) {
                        fileArrListFiles2 = new File[0];
                    } else {
                        fileArrListFiles2 = fileD2.listFiles(new H(4));
                        Intrinsics.checkNotNullExpressionValue(fileArrListFiles2, "reportDir.listFiles { di…OR_REPORT_PREFIX)))\n    }");
                    }
                    ArrayList arrayList2 = new ArrayList();
                    for (File file2 : fileArrListFiles2) {
                        Intrinsics.checkNotNullParameter(file2, "file");
                        com.facebook.internal.instrument.errorreport.a aVar4 = new com.facebook.internal.instrument.errorreport.a();
                        String name = file2.getName();
                        Intrinsics.checkNotNullExpressionValue(name, "file.name");
                        aVar4.a = name;
                        JSONObject jSONObjectG = G2.g(name);
                        if (jSONObjectG != null) {
                            aVar4.c = Long.valueOf(jSONObjectG.optLong("timestamp", 0L));
                            aVar4.b = jSONObjectG.optString("error_message", null);
                        }
                        if (aVar4.b != null && aVar4.c != null) {
                            arrayList2.add(aVar4);
                        }
                    }
                    F.t(arrayList2, new a0(i));
                    JSONArray jSONArray = new JSONArray();
                    for (int i3 = 0; i3 < arrayList2.size() && i3 < 1000; i3++) {
                        jSONArray.put(arrayList2.get(i3));
                    }
                    G2.h("error_reports", jSONArray, new com.facebook.c(arrayList2, 2));
                    return;
                }
                return;
            default:
                if (z) {
                    AtomicBoolean atomicBoolean2 = com.facebook.internal.instrument.anrreport.c.a;
                    synchronized (com.facebook.internal.instrument.anrreport.c.class) {
                        if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.internal.instrument.anrreport.c.class)) {
                            return;
                        }
                        try {
                        } catch (Throwable th15) {
                            com.facebook.internal.instrument.crashshield.a.a(com.facebook.internal.instrument.anrreport.c.class, th15);
                        }
                        if (com.facebook.internal.instrument.anrreport.c.a.getAndSet(true)) {
                            return;
                        }
                        com.facebook.o oVar3 = com.facebook.o.a;
                        if (B.c()) {
                            com.facebook.internal.instrument.anrreport.c.a();
                        }
                        int i4 = com.facebook.internal.instrument.anrreport.a.a;
                        if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.internal.instrument.anrreport.a.class)) {
                            try {
                                com.facebook.internal.instrument.anrreport.a.b.scheduleWithFixedDelay(com.facebook.internal.instrument.anrreport.a.d, 0L, 500L, TimeUnit.MILLISECONDS);
                            } catch (Throwable th16) {
                                com.facebook.internal.instrument.crashshield.a.a(com.facebook.internal.instrument.anrreport.a.class, th16);
                            }
                        }
                        return;
                    }
                }
                return;
        }
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        return AbtRegistrar.lambda$getComponents$0(c0Var);
    }

    @Override // com.google.common.base.l
    public Object get() {
        throw new IllegalStateException();
    }
}
