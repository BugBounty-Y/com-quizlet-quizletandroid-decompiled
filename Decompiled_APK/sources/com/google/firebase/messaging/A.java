package com.google.firebase.messaging;

import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import androidx.collection.C0208f;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/* loaded from: classes2.dex */
public final class A {
    public static final long i = TimeUnit.HOURS.toSeconds(8);
    public static final /* synthetic */ int j = 0;
    public final Context a;
    public final o b;
    public final m c;
    public final FirebaseMessaging d;
    public final ScheduledThreadPoolExecutor f;
    public final y h;
    public final C0208f e = new C0208f(0);
    public boolean g = false;

    public A(FirebaseMessaging firebaseMessaging, o oVar, y yVar, m mVar, Context context, ScheduledThreadPoolExecutor scheduledThreadPoolExecutor) {
        this.d = firebaseMessaging;
        this.b = oVar;
        this.h = yVar;
        this.c = mVar;
        this.a = context;
        this.f = scheduledThreadPoolExecutor;
    }

    public static void a(Task task) throws IOException {
        try {
            S3.f(task, 30L, TimeUnit.SECONDS);
        } catch (InterruptedException | TimeoutException e) {
            throw new IOException("SERVICE_NOT_AVAILABLE", e);
        } catch (ExecutionException e2) {
            Throwable cause = e2.getCause();
            if (cause instanceof IOException) {
                throw ((IOException) cause);
            }
            if (!(cause instanceof RuntimeException)) {
                throw new IOException(e2);
            }
            throw ((RuntimeException) cause);
        }
    }

    public final void b(String str) throws IOException {
        String strBlockingGetToken = this.d.blockingGetToken();
        m mVar = this.c;
        mVar.getClass();
        Bundle bundle = new Bundle();
        bundle.putString("gcm.topic", "/topics/" + str);
        a(mVar.a(mVar.c(strBlockingGetToken, "/topics/" + str, bundle)));
    }

    public final void c(String str) throws IOException {
        String strBlockingGetToken = this.d.blockingGetToken();
        m mVar = this.c;
        mVar.getClass();
        Bundle bundle = new Bundle();
        bundle.putString("gcm.topic", "/topics/" + str);
        bundle.putString("delete", "1");
        a(mVar.a(mVar.c(strBlockingGetToken, "/topics/" + str, bundle)));
    }

    public final com.google.android.gms.tasks.m d(x xVar) {
        ArrayDeque arrayDeque;
        y yVar = this.h;
        synchronized (yVar) {
            com.quizlet.remote.model.notes.e eVar = yVar.a;
            String str = xVar.c;
            eVar.getClass();
            if (!TextUtils.isEmpty(str) && !str.contains((String) eVar.d)) {
                synchronized (((ArrayDeque) eVar.e)) {
                    if (((ArrayDeque) eVar.e).add(str)) {
                        ((ScheduledThreadPoolExecutor) eVar.f).execute(new com.google.firebase.crashlytics.internal.metadata.q(eVar, 1));
                    }
                }
            }
        }
        com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f();
        synchronized (this.e) {
            try {
                String str2 = xVar.c;
                if (this.e.containsKey(str2)) {
                    arrayDeque = (ArrayDeque) this.e.get(str2);
                } else {
                    ArrayDeque arrayDeque2 = new ArrayDeque();
                    this.e.put(str2, arrayDeque2);
                    arrayDeque = arrayDeque2;
                }
                arrayDeque.add(fVar);
            } catch (Throwable th) {
                throw th;
            }
        }
        return fVar.a;
    }

    public final synchronized void e(boolean z) {
        this.g = z;
    }

    public final void f() {
        boolean z;
        if (this.h.a() != null) {
            synchronized (this) {
                z = this.g;
            }
            if (z) {
                return;
            }
            h(0L);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x003d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean g() throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 269
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.messaging.A.g():boolean");
    }

    public final void h(long j2) {
        this.f.schedule(new C(this, this.a, this.b, Math.min(Math.max(30L, 2 * j2), i)), j2, TimeUnit.SECONDS);
        e(true);
    }
}
