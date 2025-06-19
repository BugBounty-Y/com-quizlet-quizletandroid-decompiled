package com.google.firebase.crashlytics;

import android.os.Bundle;
import android.util.Log;
import androidx.emoji2.text.f;
import androidx.webkit.internal.p;
import androidx.work.impl.model.l;
import com.google.firebase.heartbeatinfo.e;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements com.google.firebase.crashlytics.internal.breadcrumbs.a, com.google.firebase.crashlytics.internal.analytics.a, com.google.firebase.inject.a {
    public final /* synthetic */ f a;

    public /* synthetic */ a(f fVar) {
        this.a = fVar;
    }

    @Override // com.google.firebase.inject.a
    public void i(com.google.firebase.inject.b bVar) {
        f fVar = this.a;
        fVar.getClass();
        Log.isLoggable("FirebaseCrashlytics", 3);
        com.google.firebase.analytics.connector.b bVar2 = (com.google.firebase.analytics.connector.b) bVar.get();
        com.airbnb.lottie.network.c cVar = new com.airbnb.lottie.network.c(bVar2, 26);
        l lVar = new l(12);
        com.google.firebase.analytics.connector.c cVar2 = (com.google.firebase.analytics.connector.c) bVar2;
        e eVarB = cVar2.b(lVar, "clx");
        if (eVarB == null) {
            Log.isLoggable("FirebaseCrashlytics", 3);
            e eVarB2 = cVar2.b(lVar, "crash");
            if (eVarB2 != null) {
                Log.w("FirebaseCrashlytics", "A new version of the Google Analytics for Firebase SDK is now available. For improved performance and compatibility with Crashlytics, please update to the latest version.", null);
            }
            eVarB = eVarB2;
        }
        if (eVarB == null) {
            Log.w("FirebaseCrashlytics", "Could not register Firebase Analytics listener; a listener is already registered.", null);
            return;
        }
        Log.isLoggable("FirebaseCrashlytics", 3);
        p pVar = new p(24, false);
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        com.quizlet.data.repository.user.a aVar = new com.quizlet.data.repository.user.a(cVar);
        synchronized (fVar) {
            try {
                Iterator it2 = ((ArrayList) fVar.b).iterator();
                while (it2.hasNext()) {
                    pVar.k((com.google.firebase.crashlytics.internal.common.p) it2.next());
                }
                lVar.c = pVar;
                lVar.b = aVar;
                fVar.c = pVar;
                fVar.a = aVar;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.firebase.crashlytics.internal.breadcrumbs.a
    public void k(com.google.firebase.crashlytics.internal.common.p pVar) {
        f fVar = this.a;
        synchronized (fVar) {
            if (((com.google.firebase.crashlytics.internal.breadcrumbs.a) fVar.c) instanceof com.google.firebase.crashlytics.internal.breadcrumbs.b) {
                ((ArrayList) fVar.b).add(pVar);
            }
            ((com.google.firebase.crashlytics.internal.breadcrumbs.a) fVar.c).k(pVar);
        }
    }

    @Override // com.google.firebase.crashlytics.internal.analytics.a
    public void n(Bundle bundle) {
        ((com.google.firebase.crashlytics.internal.analytics.a) this.a.a).n(bundle);
    }
}
