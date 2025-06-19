package com.google.firebase.messaging;

import android.content.Context;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.webkit.WebView;
import com.google.android.gms.internal.ads.AbstractC2025es;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1732Mb;
import com.google.android.gms.internal.ads.C1942cw;
import com.google.android.gms.internal.ads.C2107gm;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2499pr;
import com.google.android.gms.internal.ads.C2574rh;
import com.google.android.gms.internal.ads.Fv;
import com.google.android.gms.internal.ads.InterfaceC2316lg;
import com.google.android.gms.internal.ads.InterfaceC2529qe;
import com.google.android.gms.internal.ads.RunnableFutureC2161hw;
import com.google.android.gms.internal.ads.ScheduledFutureC1855aw;
import com.google.android.gms.internal.ads.Wp;
import com.google.android.gms.internal.ads.Yv;
import java.net.URL;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.O;

/* loaded from: classes2.dex */
public class u implements com.android.volley.j, com.perimeterx.mobile_sdk.web_view_interception.f {
    public static u e;
    public Object a;
    public Object b;
    public Object c;
    public Object d;

    public u(View view, InterfaceC2529qe interfaceC2529qe, InterfaceC2316lg interfaceC2316lg, Wp wp) {
        this.b = view;
        this.d = interfaceC2529qe;
        this.a = interfaceC2316lg;
        this.c = wp;
    }

    public static synchronized u d() {
        try {
            if (e == null) {
                e = new u(0);
            }
        } catch (Throwable th) {
            throw th;
        }
        return e;
    }

    @Override // com.perimeterx.mobile_sdk.web_view_interception.f
    public void a(com.google.android.material.floatingactionbutton.c challengeEvent) {
        androidx.constraintlayout.core.widgets.analyzer.f fVar;
        androidx.constraintlayout.core.widgets.analyzer.f fVar2;
        com.perimeterx.mobile_sdk.doctor_app.model.i iVar;
        Intrinsics.checkNotNullParameter(challengeEvent, "challengeEvent");
        if (((com.perimeterx.mobile_sdk.session.l) this.a) != null) {
            Intrinsics.checkNotNullParameter(challengeEvent, "challengeEvent");
            com.perimeterx.mobile_sdk.web_view_interception.c cVar = (com.perimeterx.mobile_sdk.web_view_interception.c) challengeEvent.b;
            if (cVar == com.perimeterx.mobile_sdk.web_view_interception.c.b && (fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j) != null && fVar2.h() && (iVar = ((com.perimeterx.mobile_sdk.doctor_app.model.d) fVar2.i).f) != null) {
                iVar.b = true;
            }
            if (cVar == com.perimeterx.mobile_sdk.web_view_interception.c.e && (fVar = androidx.constraintlayout.core.widgets.analyzer.f.j) != null && fVar.h()) {
                com.perimeterx.mobile_sdk.doctor_app.model.i iVar2 = ((com.perimeterx.mobile_sdk.doctor_app.model.d) fVar.i).f;
                if (iVar2 != null) {
                    iVar2.c = true;
                }
                new Handler(Looper.getMainLooper()).post(new com.perimeterx.mobile_sdk.doctor_app.c(fVar, 3));
            }
            kotlinx.coroutines.E.A(kotlinx.coroutines.E.c(O.a), null, null, new com.perimeterx.mobile_sdk.session.g(2, 0, null), 3);
        }
    }

    public void b() {
        ReentrantLock reentrantLock = (ReentrantLock) this.d;
        reentrantLock.lock();
        Object objClone = ((ArrayList) this.c).clone();
        Intrinsics.e(objClone, "null cannot be cast to non-null type java.util.ArrayList<com.perimeterx.mobile_sdk.web_view_interception.PXWebViewBox>");
        reentrantLock.unlock();
        Iterator it2 = ((ArrayList) objClone).iterator();
        Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
        while (it2.hasNext()) {
            Object next = it2.next();
            Intrinsics.checkNotNullExpressionValue(next, "next(...)");
            com.perimeterx.mobile_sdk.web_view_interception.b bVar = (com.perimeterx.mobile_sdk.web_view_interception.b) next;
            String str = bVar.b;
            if (str != null) {
                c(bVar.a, str);
            }
        }
    }

    public void c(WebView webView, String url) {
        ArrayList arrayList;
        com.perimeterx.mobile_sdk.doctor_app.model.i iVar;
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        if (fVar != null && fVar.h() && (iVar = ((com.perimeterx.mobile_sdk.doctor_app.model.d) fVar.i).f) != null) {
            iVar.a = true;
        }
        ReentrantLock reentrantLock = (ReentrantLock) this.d;
        reentrantLock.lock();
        Iterator it2 = ((ArrayList) this.c).iterator();
        Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            Object next = it2.next();
            Intrinsics.checkNotNullExpressionValue(next, "next(...)");
            com.perimeterx.mobile_sdk.web_view_interception.b bVar = (com.perimeterx.mobile_sdk.web_view_interception.b) next;
            if (Intrinsics.b(bVar.a, webView)) {
                bVar.b = url;
                break;
            }
        }
        reentrantLock.unlock();
        if (((com.perimeterx.mobile_sdk.session.l) this.b) != null) {
            Intrinsics.checkNotNullParameter(url, "url");
            try {
                arrayList = new ArrayList();
                com.perimeterx.mobile_sdk.session.d dVarB = com.perimeterx.mobile_sdk.session.l.b(new URL(url), com.perimeterx.mobile_sdk.business_logic.b.b);
                if (dVarB != null) {
                    arrayList.addAll(dVarB.f(url));
                }
            } catch (Exception unused) {
                arrayList = new ArrayList();
            }
        } else {
            arrayList = null;
        }
        if (arrayList != null) {
            new Handler(Looper.getMainLooper()).post(new com.google.firebase.crashlytics.internal.metadata.q(arrayList, 8));
        }
    }

    public boolean e(Context context) {
        if (((Boolean) this.c) == null) {
            this.c = Boolean.valueOf(context.checkCallingOrSelfPermission("android.permission.ACCESS_NETWORK_STATE") == 0);
        }
        if (!((Boolean) this.b).booleanValue()) {
            Log.isLoggable("FirebaseMessaging", 3);
        }
        return ((Boolean) this.c).booleanValue();
    }

    public boolean f(Context context) {
        if (((Boolean) this.b) == null) {
            this.b = Boolean.valueOf(context.checkCallingOrSelfPermission("android.permission.WAKE_LOCK") == 0);
        }
        if (!((Boolean) this.b).booleanValue()) {
            Log.isLoggable("FirebaseMessaging", 3);
        }
        return ((Boolean) this.b).booleanValue();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(java.lang.String r7, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.login.common.interactors.s
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.login.common.interactors.s r0 = (com.quizlet.login.common.interactors.s) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.login.common.interactors.s r0 = new com.quizlet.login.common.interactors.s
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L39
            if (r2 == r5) goto L33
            if (r2 != r4) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r8)
            return r8
        L2b:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L33:
            com.google.firebase.messaging.u r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L51
        L39:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.login.common.interactors.t r8 = new com.quizlet.login.common.interactors.t
            r8.<init>(r7, r6, r3)
            r0.j = r6
            r0.m = r5
            java.lang.Object r7 = r6.d
            kotlinx.coroutines.y r7 = (kotlinx.coroutines.AbstractC5040y) r7
            java.lang.Object r8 = kotlinx.coroutines.E.J(r7, r8, r0)
            if (r8 != r1) goto L50
            goto L68
        L50:
            r7 = r6
        L51:
            java.lang.String r2 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r2)
            com.quizlet.login.authentication.data.i r8 = (com.quizlet.login.authentication.data.i) r8
            java.lang.Object r7 = r7.c
            androidx.compose.runtime.internal.j r7 = (androidx.compose.runtime.internal.j) r7
            r0.j = r3
            r0.m = r4
            java.lang.String r2 = "facebook"
            java.lang.Object r7 = r7.s(r8, r2, r3, r0)
            if (r7 != r1) goto L69
        L68:
            return r1
        L69:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.messaging.u.g(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public synchronized boolean h(com.android.volley.l lVar) {
        try {
            String cacheKey = lVar.getCacheKey();
            if (!((HashMap) this.a).containsKey(cacheKey)) {
                ((HashMap) this.a).put(cacheKey, null);
                lVar.setNetworkRequestCompleteListener(this);
                if (com.android.volley.y.a) {
                    com.android.volley.y.a("new request, sending to network %s", cacheKey);
                }
                return false;
            }
            List arrayList = (List) ((HashMap) this.a).get(cacheKey);
            if (arrayList == null) {
                arrayList = new ArrayList();
            }
            lVar.addMarker("waiting-for-response");
            arrayList.add(lVar);
            ((HashMap) this.a).put(cacheKey, arrayList);
            if (com.android.volley.y.a) {
                com.android.volley.y.a("Request for cacheKey=%s is in flight, putting on hold.", cacheKey);
            }
            return true;
        } catch (Throwable th) {
            throw th;
        }
    }

    public synchronized void i(com.android.volley.l lVar) {
        BlockingQueue blockingQueue;
        try {
            String cacheKey = lVar.getCacheKey();
            List list = (List) ((HashMap) this.a).remove(cacheKey);
            if (list != null && !list.isEmpty()) {
                if (com.android.volley.y.a) {
                    com.android.volley.y.c("%d waiting requests for cacheKey=%s; resend to network", Integer.valueOf(list.size()), cacheKey);
                }
                com.android.volley.l lVar2 = (com.android.volley.l) list.remove(0);
                ((HashMap) this.a).put(cacheKey, list);
                lVar2.setNetworkRequestCompleteListener(this);
                if (((com.android.volley.c) this.c) != null && (blockingQueue = (BlockingQueue) this.d) != null) {
                    try {
                        blockingQueue.put(lVar2);
                    } catch (InterruptedException e2) {
                        com.android.volley.y.b("Couldn't add request to queue. %s", e2.toString());
                        Thread.currentThread().interrupt();
                        com.android.volley.c cVar = (com.android.volley.c) this.c;
                        cVar.e = true;
                        cVar.interrupt();
                    }
                }
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public C2574rh j(Set set) {
        return new C2574rh(set);
    }

    public com.google.common.util.concurrent.e k(final int i, final long j, final String str) {
        final String strL;
        com.google.android.gms.ads.internal.util.client.h hVar = (com.google.android.gms.ads.internal.util.client.h) this.a;
        if (i > hVar.a) {
            C2499pr c2499pr = (C2499pr) this.d;
            if (c2499pr == null || !hVar.d) {
                return AbstractC2025es.E(com.google.android.gms.ads.internal.util.client.j.c);
            }
            com.google.android.gms.ads.internal.j.C.k.getClass();
            com.android.volley.toolbox.d dVar = new com.android.volley.toolbox.d(2, System.currentTimeMillis(), "", str);
            C2107gm c2107gm = c2499pr.a;
            c2107gm.getClass();
            c2107gm.d(new C1732Mb(26, c2107gm, dVar));
            return AbstractC2025es.E(com.google.android.gms.ads.internal.util.client.j.d);
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.C8)).booleanValue()) {
            Uri uri = Uri.parse(str);
            String encodedQuery = uri.getEncodedQuery();
            Uri.Builder builderClearQuery = uri.buildUpon().clearQuery();
            builderClearQuery.appendQueryParameter("pa", Integer.toString(i));
            strL = android.support.v4.media.session.a.l(String.valueOf(builderClearQuery.build()), "&", encodedQuery);
        } else {
            strL = str;
        }
        Fv fv = new Fv() { // from class: com.google.android.gms.internal.ads.or
            @Override // com.google.android.gms.internal.ads.Fv
            public final com.google.common.util.concurrent.e b(Object obj) {
                com.google.android.gms.ads.internal.util.client.j jVar = (com.google.android.gms.ads.internal.util.client.j) obj;
                if (jVar != com.google.android.gms.ads.internal.util.client.j.c) {
                    return AbstractC2025es.E(jVar);
                }
                com.google.firebase.messaging.u uVar = this.a;
                com.google.android.gms.ads.internal.util.client.h hVar2 = (com.google.android.gms.ads.internal.util.client.h) uVar.a;
                long j2 = hVar2.b;
                int i2 = i;
                if (i2 != 1) {
                    j2 = (long) (hVar2.c * j);
                }
                return uVar.k(i2 + 1, j2, str);
            }
        };
        Executor executor = (Yv) this.c;
        if (j == 0) {
            final int i2 = 1;
            return AbstractC2025es.N(((C2227jd) executor).d(new Callable(this) { // from class: com.google.android.gms.internal.ads.nr
                public final /* synthetic */ com.google.firebase.messaging.u b;

                {
                    this.b = this;
                }

                @Override // java.util.concurrent.Callable
                public final Object call() {
                    switch (i2) {
                    }
                    return ((com.google.android.gms.ads.internal.util.client.k) this.b.b).zza(strL);
                }
            }), fv, executor);
        }
        final int i3 = 0;
        Callable callable = new Callable(this) { // from class: com.google.android.gms.internal.ads.nr
            public final /* synthetic */ com.google.firebase.messaging.u b;

            {
                this.b = this;
            }

            @Override // java.util.concurrent.Callable
            public final Object call() {
                switch (i3) {
                }
                return ((com.google.android.gms.ads.internal.util.client.k) this.b.b).zza(strL);
            }
        };
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        C1942cw c1942cw = (C1942cw) executor;
        c1942cw.getClass();
        RunnableFutureC2161hw runnableFutureC2161hw = new RunnableFutureC2161hw(callable);
        return AbstractC2025es.N(new ScheduledFutureC1855aw(runnableFutureC2161hw, c1942cw.c.schedule(runnableFutureC2161hw, j, timeUnit)), fv, c1942cw);
    }

    public u(com.google.android.gms.ads.internal.util.client.h hVar, com.google.android.gms.ads.internal.util.client.k kVar, Yv yv, C2499pr c2499pr) {
        this.a = hVar;
        this.b = kVar;
        this.c = yv;
        this.d = c2499pr;
    }

    public u(io.ktor.client.plugins.api.d apiClient, com.quizlet.qutils.string.c state, androidx.compose.runtime.internal.j handleLoginResponseUseCase, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(apiClient, "apiClient");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(handleLoginResponseUseCase, "handleLoginResponseUseCase");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = apiClient;
        this.b = state;
        this.c = handleLoginResponseUseCase;
        this.d = ioDispatcher;
    }

    public u(int i) {
        switch (i) {
            case 6:
                this.c = new ArrayList();
                this.d = new ReentrantLock();
                break;
            default:
                this.a = null;
                this.b = null;
                this.c = null;
                this.d = new ArrayDeque();
                break;
        }
    }
}
