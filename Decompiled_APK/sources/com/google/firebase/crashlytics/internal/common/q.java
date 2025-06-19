package com.google.firebase.crashlytics.internal.common;

import android.content.Context;
import android.util.Log;
import androidx.appcompat.app.Q;
import java.io.File;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class q {
    public final Context a;
    public final com.quizlet.data.repository.studysetwithcreatorinclass.g b;
    public final com.quizlet.data.repository.explanations.myexplanations.a c;
    public final long d;
    public com.quizlet.data.repository.activitycenter.b e;
    public com.quizlet.data.repository.activitycenter.b f;
    public m g;
    public final v h;
    public final com.google.firebase.crashlytics.internal.persistence.c i;
    public final com.google.firebase.crashlytics.a j;
    public final com.google.firebase.crashlytics.a k;
    public final h l;
    public final com.google.firebase.crashlytics.internal.a m;
    public final Q n;
    public final com.google.firebase.crashlytics.internal.concurrency.d o;

    public q(com.google.firebase.h hVar, v vVar, com.google.firebase.crashlytics.internal.a aVar, com.quizlet.data.repository.studysetwithcreatorinclass.g gVar, com.google.firebase.crashlytics.a aVar2, com.google.firebase.crashlytics.a aVar3, com.google.firebase.crashlytics.internal.persistence.c cVar, h hVar2, Q q, com.google.firebase.crashlytics.internal.concurrency.d dVar) {
        this.b = gVar;
        hVar.a();
        this.a = hVar.a;
        this.h = vVar;
        this.m = aVar;
        this.j = aVar2;
        this.k = aVar3;
        this.i = cVar;
        this.l = hVar2;
        this.n = q;
        this.o = dVar;
        this.d = System.currentTimeMillis();
        this.c = new com.quizlet.data.repository.explanations.myexplanations.a(12);
    }

    public final void a(com.google.android.datatransport.cct.internal.s sVar) {
        com.google.firebase.crashlytics.internal.concurrency.d.a();
        com.google.firebase.crashlytics.internal.concurrency.d.a();
        this.e.e();
        Log.isLoggable("FirebaseCrashlytics", 2);
        try {
            try {
                this.j.k(new p(this));
                this.g.g();
                if (!sVar.l().b.a) {
                    Log.isLoggable("FirebaseCrashlytics", 3);
                    throw new RuntimeException("Collection of crash reports disabled in Crashlytics settings.");
                }
                if (!this.g.d(sVar)) {
                    Log.w("FirebaseCrashlytics", "Previous sessions could not be finalized.", null);
                }
                this.g.h(((com.google.android.gms.tasks.f) ((AtomicReference) sVar.i).get()).a);
                c();
            } catch (Exception e) {
                Log.e("FirebaseCrashlytics", "Crashlytics encountered a problem during asynchronous initialization.", e);
                c();
            }
        } catch (Throwable th) {
            c();
            throw th;
        }
    }

    public final void b(com.google.android.datatransport.cct.internal.s sVar) {
        Future<?> futureSubmit = this.o.a.a.submit(new n(this, sVar, 1));
        Log.isLoggable("FirebaseCrashlytics", 3);
        try {
            futureSubmit.get(3L, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Log.e("FirebaseCrashlytics", "Crashlytics was interrupted during initialization.", e);
            Thread.currentThread().interrupt();
        } catch (ExecutionException e2) {
            Log.e("FirebaseCrashlytics", "Crashlytics encountered a problem during initialization.", e2);
        } catch (TimeoutException e3) {
            Log.e("FirebaseCrashlytics", "Crashlytics timed out during initialization.", e3);
        }
    }

    public final void c() {
        com.google.firebase.crashlytics.internal.concurrency.d.a();
        try {
            com.quizlet.data.repository.activitycenter.b bVar = this.e;
            String str = (String) bVar.b;
            com.google.firebase.crashlytics.internal.persistence.c cVar = (com.google.firebase.crashlytics.internal.persistence.c) bVar.c;
            cVar.getClass();
            if (new File(cVar.c, str).delete()) {
                return;
            }
            Log.w("FirebaseCrashlytics", "Initialization marker file was not properly removed.", null);
        } catch (Exception e) {
            Log.e("FirebaseCrashlytics", "Problem encountered deleting Crashlytics initialization marker.", e);
        }
    }
}
