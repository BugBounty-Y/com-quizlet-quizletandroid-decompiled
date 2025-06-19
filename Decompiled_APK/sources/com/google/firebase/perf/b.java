package com.google.firebase.perf;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import com.google.android.gms.internal.mlkit_vision_common.E4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3692p;
import com.google.firebase.h;
import com.google.firebase.i;
import com.google.firebase.perf.config.RemoteConfigManager;
import com.google.firebase.perf.metrics.Trace;
import com.google.firebase.perf.session.SessionManager;
import com.google.firebase.perf.transport.e;
import com.google.firebase.perf.transport.f;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes2.dex */
public final class b {
    public static final com.google.firebase.perf.logging.a b = com.google.firebase.perf.logging.a.d();
    public final ConcurrentHashMap a = new ConcurrentHashMap();

    public b(h hVar, com.google.firebase.inject.b bVar, com.google.firebase.installations.d dVar, com.google.firebase.inject.b bVar2, RemoteConfigManager remoteConfigManager, com.google.firebase.perf.config.a aVar, SessionManager sessionManager) {
        Bundle bundle;
        if (hVar == null) {
            new com.google.firebase.perf.util.c(new Bundle());
            return;
        }
        f fVar = f.s;
        fVar.d = hVar;
        hVar.a();
        i iVar = hVar.c;
        fVar.p = iVar.g;
        fVar.f = dVar;
        fVar.g = bVar2;
        fVar.i.execute(new e(fVar, 1));
        hVar.a();
        Context context = hVar.a;
        try {
            bundle = context.getPackageManager().getApplicationInfo(context.getPackageName(), 128).metaData;
        } catch (PackageManager.NameNotFoundException | NullPointerException e) {
            e.getMessage();
            bundle = null;
        }
        com.google.firebase.perf.util.c cVar = bundle != null ? new com.google.firebase.perf.util.c(bundle) : new com.google.firebase.perf.util.c();
        remoteConfigManager.setFirebaseRemoteConfigProvider(bVar);
        aVar.b = cVar;
        com.google.firebase.perf.config.a.d.b = AbstractC3692p.a(context);
        aVar.c.c(context);
        sessionManager.setApplicationContext(context);
        Boolean boolG = aVar.g();
        com.google.firebase.perf.logging.a aVar2 = b;
        if (aVar2.b) {
            if (boolG != null ? boolG.booleanValue() : h.c().h()) {
                hVar.a();
                String strConcat = "Firebase Performance Monitoring is successfully initialized! In a minute, visit the Firebase console to view your data: ".concat(E4.a(iVar.g, context.getPackageName()).concat("/trends?utm_source=perf-android-sdk&utm_medium=android-ide"));
                if (aVar2.b) {
                    aVar2.a.getClass();
                    Log.i("FirebasePerformance", strConcat);
                }
            }
        }
    }

    public static Trace a(String str) {
        Trace traceC = Trace.c(str);
        traceC.start();
        return traceC;
    }
}
