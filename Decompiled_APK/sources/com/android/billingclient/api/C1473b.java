package com.android.billingclient.api;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import androidx.appcompat.app.Q;
import androidx.appcompat.widget.C0122z;
import androidx.camera.camera2.internal.p0;
import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import com.google.android.gms.internal.play_billing.C3850y;
import com.google.android.gms.internal.play_billing.InterfaceC3788d;
import com.google.android.gms.internal.play_billing.InterfaceExecutorServiceC3848x0;
import com.google.android.gms.internal.play_billing.J1;
import com.google.android.gms.internal.play_billing.K1;
import com.google.android.gms.internal.play_billing.L1;
import com.google.android.gms.internal.play_billing.M1;
import com.google.android.gms.internal.play_billing.N1;
import com.google.android.gms.internal.play_billing.O1;
import com.google.android.gms.internal.play_billing.T1;
import com.google.android.gms.internal.play_billing.U1;
import com.google.android.gms.internal.play_billing.W1;
import com.google.android.gms.internal.play_billing.Y1;
import com.google.android.gms.internal.play_billing.h2;
import com.google.android.gms.internal.play_billing.i2;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.android.billingclient.api.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C1473b {
    public final com.quizlet.shared.usecase.folderstudymaterials.b A;
    public final boolean B;
    public ExecutorService C;
    public volatile InterfaceExecutorServiceC3848x0 D;
    public final Long E;
    public final Object a;
    public volatile int b;
    public final String c;
    public final Handler d;
    public volatile p0 e;
    public final Context f;
    public final androidx.work.impl.model.c g;
    public volatile InterfaceC3788d h;
    public volatile q i;
    public boolean j;
    public boolean k;
    public int l;
    public boolean m;
    public boolean n;
    public boolean o;
    public boolean p;
    public boolean q;
    public boolean r;
    public boolean s;
    public boolean t;
    public boolean u;
    public boolean v;
    public boolean w;
    public boolean x;
    public boolean y;
    public boolean z;

    public C1473b(com.quizlet.shared.usecase.folderstudymaterials.b bVar, Context context) {
        this.a = new Object();
        this.b = 0;
        this.d = new Handler(Looper.getMainLooper());
        this.l = 0;
        long jNextLong = new Random().nextLong();
        this.E = Long.valueOf(jNextLong);
        this.c = l();
        this.f = context.getApplicationContext();
        T1 t1R = U1.r();
        String strL = l();
        t1R.e();
        U1.q((U1) t1R.b, strL);
        String packageName = this.f.getPackageName();
        t1R.e();
        U1.p((U1) t1R.b, packageName);
        t1R.e();
        U1.o((U1) t1R.b, jNextLong);
        this.g = new androidx.work.impl.model.c(this.f, (U1) t1R.c());
        AbstractC3819n0.f("BillingClient", "Billing client should have a valid listener but the provided is null.");
        this.e = new p0(this.f, null, this.g);
        this.A = bVar;
        this.f.getPackageName();
    }

    public static Future i(Callable callable, long j, Runnable runnable, Handler handler, ExecutorService executorService) {
        try {
            Future futureSubmit = executorService.submit(callable);
            handler.postDelayed(new com.google.common.util.concurrent.d(8, futureSubmit, runnable), (long) (j * 0.95d));
            return futureSubmit;
        } catch (Exception e) {
            AbstractC3819n0.g("BillingClient", "Async task throws exception!", e);
            return null;
        }
    }

    public static String l() {
        try {
            return (String) Class.forName("com.android.billingclient.ktx.BuildConfig").getField("VERSION_NAME").get(null);
        } catch (Exception unused) {
            return com.android.billingclient.a.a;
        }
    }

    public final void A(e eVar) {
        if (Thread.interrupted()) {
            return;
        }
        this.d.post(new com.google.common.util.concurrent.d(9, this, eVar));
    }

    public void a(C1472a c1472a, com.google.android.material.search.a aVar) {
        if (!d()) {
            e eVar = A.k;
            x(2, 3, eVar);
            aVar.a(eVar);
            return;
        }
        if (TextUtils.isEmpty(c1472a.b)) {
            AbstractC3819n0.f("BillingClient", "Please provide a valid purchase token.");
            e eVar2 = A.h;
            x(26, 3, eVar2);
            aVar.a(eVar2);
            return;
        }
        if (!this.o) {
            e eVar3 = A.b;
            x(27, 3, eVar3);
            aVar.a(eVar3);
        } else if (i(new n(this, aVar, c1472a, 3), 30000L, new androidx.camera.core.impl.utils.futures.h(10, this, aVar), v(), m()) == null) {
            e eVarJ = j();
            x(25, 3, eVarJ);
            aVar.a(eVarJ);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:46:0x003e A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void b() {
        /*
            r5 = this;
            r0 = 12
            r5.z(r0)
            java.lang.Object r0 = r5.a
            monitor-enter(r0)
            androidx.camera.camera2.internal.p0 r1 = r5.e     // Catch: java.lang.Throwable -> L21
            if (r1 == 0) goto L29
            androidx.camera.camera2.internal.p0 r1 = r5.e     // Catch: java.lang.Throwable -> L21
            java.lang.Object r2 = r1.e     // Catch: java.lang.Throwable -> L21
            com.android.billingclient.api.C r2 = (com.android.billingclient.api.C) r2     // Catch: java.lang.Throwable -> L21
            java.lang.Object r3 = r1.c     // Catch: java.lang.Throwable -> L21
            android.content.Context r3 = (android.content.Context) r3     // Catch: java.lang.Throwable -> L21
            r2.c(r3)     // Catch: java.lang.Throwable -> L21
            java.lang.Object r1 = r1.f     // Catch: java.lang.Throwable -> L21
            com.android.billingclient.api.C r1 = (com.android.billingclient.api.C) r1     // Catch: java.lang.Throwable -> L21
            r1.c(r3)     // Catch: java.lang.Throwable -> L21
            goto L29
        L21:
            r1 = move-exception
            java.lang.String r2 = "BillingClient"
            java.lang.String r3 = "There was an exception while shutting down broadcast manager while ending connection!"
            com.google.android.gms.internal.play_billing.AbstractC3819n0.g(r2, r3, r1)     // Catch: java.lang.Throwable -> L52
        L29:
            java.lang.String r1 = "BillingClient"
            java.lang.String r2 = "Unbinding from service."
            com.google.android.gms.internal.play_billing.AbstractC3819n0.e(r1, r2)     // Catch: java.lang.Throwable -> L34
            r5.q()     // Catch: java.lang.Throwable -> L34
            goto L3c
        L34:
            r1 = move-exception
            java.lang.String r2 = "BillingClient"
            java.lang.String r3 = "There was an exception while unbinding from the service while ending connection!"
            com.google.android.gms.internal.play_billing.AbstractC3819n0.g(r2, r3, r1)     // Catch: java.lang.Throwable -> L52
        L3c:
            r1 = 3
            monitor-enter(r5)     // Catch: java.lang.Throwable -> L56
            java.util.concurrent.ExecutorService r2 = r5.C     // Catch: java.lang.Throwable -> L4c
            if (r2 == 0) goto L4a
            r2.shutdownNow()     // Catch: java.lang.Throwable -> L4c
            r2 = 0
            r5.C = r2     // Catch: java.lang.Throwable -> L4c
            r5.D = r2     // Catch: java.lang.Throwable -> L4c
        L4a:
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L56
            goto L4e
        L4c:
            r2 = move-exception
            goto L54
        L4e:
            r5.p(r1)     // Catch: java.lang.Throwable -> L52
            goto L5f
        L52:
            r1 = move-exception
            goto L66
        L54:
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L4c
            throw r2     // Catch: java.lang.Throwable -> L56
        L56:
            r2 = move-exception
            java.lang.String r3 = "BillingClient"
            java.lang.String r4 = "There was an exception while shutting down the executor service while ending connection!"
            com.google.android.gms.internal.play_billing.AbstractC3819n0.g(r3, r4, r2)     // Catch: java.lang.Throwable -> L61
            goto L4e
        L5f:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L52
            return
        L61:
            r2 = move-exception
            r5.p(r1)     // Catch: java.lang.Throwable -> L52
            throw r2     // Catch: java.lang.Throwable -> L52
        L66:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L52
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.billingclient.api.C1473b.b():void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00d3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.android.billingclient.api.e c(java.lang.String r17) {
        /*
            Method dump skipped, instructions count: 558
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.billingclient.api.C1473b.c(java.lang.String):com.android.billingclient.api.e");
    }

    public final boolean d() {
        boolean z;
        synchronized (this.a) {
            try {
                z = false;
                if (this.b == 2 && this.h != null && this.i != null) {
                    z = true;
                }
            } finally {
            }
        }
        return z;
    }

    /* JADX WARN: Removed duplicated region for block: B:213:0x053c  */
    /* JADX WARN: Removed duplicated region for block: B:217:0x0545  */
    /* JADX WARN: Removed duplicated region for block: B:219:0x0549  */
    /* JADX WARN: Removed duplicated region for block: B:220:0x054c  */
    /* JADX WARN: Removed duplicated region for block: B:224:0x0584 A[Catch: Exception -> 0x0590, CancellationException -> 0x0593, TimeoutException -> 0x0596, TRY_ENTER, TryCatch #6 {CancellationException -> 0x0593, TimeoutException -> 0x0596, Exception -> 0x0590, blocks: (B:224:0x0584, B:232:0x0599, B:234:0x05ae, B:259:0x0637, B:258:0x0625, B:248:0x0602, B:261:0x063e), top: B:282:0x0582 }] */
    /* JADX WARN: Removed duplicated region for block: B:232:0x0599 A[Catch: Exception -> 0x0590, CancellationException -> 0x0593, TimeoutException -> 0x0596, TryCatch #6 {CancellationException -> 0x0593, TimeoutException -> 0x0596, Exception -> 0x0590, blocks: (B:224:0x0584, B:232:0x0599, B:234:0x05ae, B:259:0x0637, B:258:0x0625, B:248:0x0602, B:261:0x063e), top: B:282:0x0582 }] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00a8  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.android.billingclient.api.e e(android.app.Activity r28, final androidx.compose.material.ripple.r r29) {
        /*
            Method dump skipped, instructions count: 1697
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.billingclient.api.C1473b.e(android.app.Activity, androidx.compose.material.ripple.r):com.android.billingclient.api.e");
    }

    public void f(Q q, com.quizlet.billing.manager.a aVar) {
        if (!d()) {
            e eVar = A.k;
            x(2, 7, eVar);
            aVar.a(eVar, new ArrayList());
        } else {
            if (!this.t) {
                AbstractC3819n0.f("BillingClient", "Querying product details is not supported.");
                e eVar2 = A.s;
                x(20, 7, eVar2);
                aVar.a(eVar2, new ArrayList());
                return;
            }
            if (i(new n(this, q, aVar, 0), 30000L, new androidx.camera.core.impl.utils.futures.h(9, this, aVar), v(), m()) == null) {
                e eVarJ = j();
                x(25, 7, eVarJ);
                aVar.a(eVarJ, new ArrayList());
            }
        }
    }

    public final void g(m mVar, com.quizlet.billing.manager.a aVar) {
        if (!d()) {
            e eVar = A.k;
            x(2, 9, eVar);
            C3850y c3850y = com.google.android.gms.internal.play_billing.B.b;
            aVar.b(eVar, com.google.android.gms.internal.play_billing.Q.e);
            return;
        }
        String str = mVar.a;
        if (TextUtils.isEmpty(str)) {
            AbstractC3819n0.f("BillingClient", "Please provide a valid product type.");
            e eVar2 = A.f;
            x(50, 9, eVar2);
            C3850y c3850y2 = com.google.android.gms.internal.play_billing.B.b;
            aVar.b(eVar2, com.google.android.gms.internal.play_billing.Q.e);
            return;
        }
        if (i(new n(this, str, aVar, 1), 30000L, new androidx.camera.core.impl.utils.futures.h(8, this, aVar), v(), m()) == null) {
            e eVarJ = j();
            x(25, 9, eVarJ);
            C3850y c3850y3 = com.google.android.gms.internal.play_billing.B.b;
            aVar.b(eVarJ, com.google.android.gms.internal.play_billing.Q.e);
        }
    }

    public void h(com.quizlet.billing.manager.f fVar) {
        e result;
        synchronized (this.a) {
            try {
                if (d()) {
                    result = w();
                } else if (this.b == 1) {
                    AbstractC3819n0.f("BillingClient", "Client is already in the process of connecting to billing service.");
                    result = A.e;
                    x(37, 6, result);
                } else if (this.b == 3) {
                    AbstractC3819n0.f("BillingClient", "Client was already closed and can't be reused. Please create another instance.");
                    result = A.k;
                    x(38, 6, result);
                } else {
                    p(1);
                    q();
                    AbstractC3819n0.e("BillingClient", "Starting in-app billing setup.");
                    this.i = new q(this, fVar);
                    Intent intent = new Intent("com.android.vending.billing.InAppBillingService.BIND");
                    intent.setPackage("com.android.vending");
                    List<ResolveInfo> listQueryIntentServices = this.f.getPackageManager().queryIntentServices(intent, 0);
                    int i = 41;
                    if (listQueryIntentServices == null || listQueryIntentServices.isEmpty()) {
                        p(0);
                        AbstractC3819n0.e("BillingClient", "Billing service unavailable on device.");
                        result = A.c;
                        x(i, 6, result);
                    } else {
                        ServiceInfo serviceInfo = listQueryIntentServices.get(0).serviceInfo;
                        i = 40;
                        if (serviceInfo != null) {
                            String str = serviceInfo.packageName;
                            String str2 = serviceInfo.name;
                            if (!Objects.equals(str, "com.android.vending") || str2 == null) {
                                AbstractC3819n0.f("BillingClient", "The device doesn't have valid Play Store.");
                            } else {
                                ComponentName componentName = new ComponentName(str, str2);
                                Intent intent2 = new Intent(intent);
                                intent2.setComponent(componentName);
                                intent2.putExtra("playBillingLibraryVersion", this.c);
                                synchronized (this.a) {
                                    try {
                                        if (this.b == 2) {
                                            result = w();
                                        } else if (this.b != 1) {
                                            AbstractC3819n0.f("BillingClient", "Client state no longer CONNECTING, returning service disconnected.");
                                            result = A.k;
                                            x(117, 6, result);
                                        } else {
                                            q qVar = this.i;
                                            if (this.f.bindService(intent2, qVar, 1)) {
                                                AbstractC3819n0.e("BillingClient", "Service was bonded successfully.");
                                                result = null;
                                            } else {
                                                AbstractC3819n0.f("BillingClient", "Connection to Billing service is blocked.");
                                                i = 39;
                                            }
                                        }
                                    } finally {
                                    }
                                }
                            }
                        } else {
                            AbstractC3819n0.f("BillingClient", "The device doesn't have valid Play Store.");
                        }
                        p(0);
                        AbstractC3819n0.e("BillingClient", "Billing service unavailable on device.");
                        result = A.c;
                        x(i, 6, result);
                    }
                }
            } finally {
            }
        }
        if (result != null) {
            fVar.getClass();
            Intrinsics.checkNotNullParameter(result, "result");
            if (fVar.f.s() || fVar.f.r()) {
                return;
            }
            fVar.f.onSuccess(Integer.valueOf(result.a));
        }
    }

    public final e j() {
        int[] iArr = {0, 3};
        synchronized (this.a) {
            for (int i = 0; i < 2; i++) {
                if (this.b == iArr[i]) {
                    return A.k;
                }
            }
            return A.i;
        }
    }

    public final void k() {
        if (TextUtils.isEmpty(null)) {
            this.f.getPackageName();
        }
    }

    public final synchronized ExecutorService m() {
        try {
            if (this.C == null) {
                this.C = Executors.newFixedThreadPool(AbstractC3819n0.a, new p());
            }
        } catch (Throwable th) {
            throw th;
        }
        return this.C;
    }

    public final void n(K1 k1) {
        try {
            androidx.work.impl.model.c cVar = this.g;
            int i = this.l;
            cVar.getClass();
            try {
                T1 t1 = (T1) ((U1) cVar.b).g();
                t1.e();
                U1.n((U1) t1.b, i);
                cVar.b = (U1) t1.c();
                cVar.C(k1);
            } catch (Throwable th) {
                AbstractC3819n0.g("BillingLogger", "Unable to log.", th);
            }
        } catch (Throwable th2) {
            AbstractC3819n0.g("BillingClient", "Unable to log.", th2);
        }
    }

    public final void o(M1 m1) {
        try {
            androidx.work.impl.model.c cVar = this.g;
            int i = this.l;
            cVar.getClass();
            try {
                T1 t1 = (T1) ((U1) cVar.b).g();
                t1.e();
                U1.n((U1) t1.b, i);
                cVar.b = (U1) t1.c();
                cVar.D(m1);
            } catch (Throwable th) {
                AbstractC3819n0.g("BillingLogger", "Unable to log.", th);
            }
        } catch (Throwable th2) {
            AbstractC3819n0.g("BillingClient", "Unable to log.", th2);
        }
    }

    public final void p(int i) {
        synchronized (this.a) {
            try {
                if (this.b == 3) {
                    return;
                }
                int i2 = this.b;
                AbstractC3819n0.e("BillingClient", "Setting clientState from " + (i2 != 0 ? i2 != 1 ? i2 != 2 ? "CLOSED" : "CONNECTED" : "CONNECTING" : "DISCONNECTED") + " to " + (i != 0 ? i != 1 ? i != 2 ? "CLOSED" : "CONNECTED" : "CONNECTING" : "DISCONNECTED"));
                this.b = i;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void q() {
        synchronized (this.a) {
            if (this.i != null) {
                try {
                    this.f.unbindService(this.i);
                } catch (Throwable th) {
                    try {
                        AbstractC3819n0.g("BillingClient", "There was an exception while unbinding service!", th);
                        this.h = null;
                        this.i = null;
                    } finally {
                        this.h = null;
                        this.i = null;
                    }
                }
            }
        }
    }

    public final C0122z r(e eVar, int i, String str, Exception exc) {
        AbstractC3819n0.g("BillingClient", str, exc);
        y(i, 7, eVar, y.a(exc));
        return new C0122z(eVar.a, eVar.b, new ArrayList());
    }

    public final androidx.work.impl.model.e s(e eVar, int i, String str, Exception exc) {
        y(i, 9, eVar, y.a(exc));
        AbstractC3819n0.g("BillingClient", str, exc);
        return new androidx.work.impl.model.e(eVar, (ArrayList) null);
    }

    public final void t(int i, int i2, e eVar) {
        M1 m1 = null;
        K1 k1 = null;
        if (eVar.a == 0) {
            int i3 = y.a;
            try {
                L1 l1Q = M1.q();
                l1Q.e();
                M1.p((M1) l1Q.b, 5);
                W1 w1O = Y1.o();
                w1O.e();
                Y1.n((Y1) w1O.b, i2);
                Y1 y1 = (Y1) w1O.c();
                l1Q.e();
                M1.n((M1) l1Q.b, y1);
                m1 = (M1) l1Q.c();
            } catch (Exception e) {
                AbstractC3819n0.g("BillingLogger", "Unable to create logging payload", e);
            }
            o(m1);
            return;
        }
        int i4 = y.a;
        try {
            J1 j1R = K1.r();
            N1 n1R = O1.r();
            n1R.f(eVar.a);
            String str = eVar.b;
            n1R.e();
            O1.o((O1) n1R.b, str);
            n1R.g(i);
            j1R.f(n1R);
            j1R.g(5);
            W1 w1O2 = Y1.o();
            w1O2.e();
            Y1.n((Y1) w1O2.b, i2);
            Y1 y12 = (Y1) w1O2.c();
            j1R.e();
            K1.p((K1) j1R.b, y12);
            k1 = (K1) j1R.c();
        } catch (Exception e2) {
            AbstractC3819n0.g("BillingLogger", "Unable to create logging payload", e2);
        }
        n(k1);
    }

    public final void u(com.google.android.material.search.a aVar, e eVar, int i, Exception exc) {
        AbstractC3819n0.g("BillingClient", "Error in acknowledge purchase!", exc);
        y(i, 3, eVar, y.a(exc));
        aVar.a(eVar);
    }

    public final Handler v() {
        return Looper.myLooper() == null ? this.d : new Handler(Looper.myLooper());
    }

    public final e w() {
        AbstractC3819n0.e("BillingClient", "Service connection is valid. No need to re-initialize.");
        L1 l1Q = M1.q();
        l1Q.e();
        M1.p((M1) l1Q.b, 6);
        h2 h2VarO = i2.o();
        h2VarO.e();
        i2.n((i2) h2VarO.b);
        l1Q.e();
        M1.o((M1) l1Q.b, (i2) h2VarO.c());
        o((M1) l1Q.c());
        return A.j;
    }

    public final void x(int i, int i2, e eVar) {
        try {
            n(y.b(i, i2, eVar));
        } catch (Throwable th) {
            AbstractC3819n0.g("BillingClient", "Unable to log.", th);
        }
    }

    public final void y(int i, int i2, e eVar, String str) {
        try {
            n(y.c(i, i2, eVar, str));
        } catch (Throwable th) {
            AbstractC3819n0.g("BillingClient", "Unable to log.", th);
        }
    }

    public final void z(int i) {
        try {
            o(y.d(i));
        } catch (Throwable th) {
            AbstractC3819n0.g("BillingClient", "Unable to log.", th);
        }
    }

    public C1473b(com.quizlet.shared.usecase.folderstudymaterials.b bVar, Context context, k kVar) {
        String strL = l();
        this.a = new Object();
        this.b = 0;
        this.d = new Handler(Looper.getMainLooper());
        this.l = 0;
        long jNextLong = new Random().nextLong();
        this.E = Long.valueOf(jNextLong);
        this.c = strL;
        this.f = context.getApplicationContext();
        T1 t1R = U1.r();
        t1R.e();
        U1.q((U1) t1R.b, strL);
        String packageName = this.f.getPackageName();
        t1R.e();
        U1.p((U1) t1R.b, packageName);
        t1R.e();
        U1.o((U1) t1R.b, jNextLong);
        this.g = new androidx.work.impl.model.c(this.f, (U1) t1R.c());
        if (kVar == null) {
            AbstractC3819n0.f("BillingClient", "Billing client should have a valid listener but the provided is null.");
        }
        this.e = new p0(this.f, kVar, this.g);
        this.A = bVar;
        this.B = false;
        this.f.getPackageName();
    }
}
