package com.google.android.gms.ads.internal;

import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Looper;
import android.util.Base64;
import android.view.MotionEvent;
import android.view.View;
import androidx.appcompat.app.Q;
import androidx.browser.customtabs.k;
import com.bumptech.glide.manager.o;
import com.bumptech.glide.manager.p;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.util.F;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.ads.internal.util.y;
import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.Bs;
import com.google.android.gms.internal.ads.C2371ms;
import com.google.android.gms.internal.ads.C2598s4;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.C2641t4;
import com.google.android.gms.internal.ads.C2728v5;
import com.google.android.gms.internal.ads.C2770w4;
import com.google.android.gms.internal.ads.C2813x4;
import com.google.android.gms.internal.ads.D4;
import com.google.android.gms.internal.ads.L4;
import com.google.android.gms.internal.ads.N4;
import com.google.android.gms.internal.ads.O4;
import com.google.android.gms.internal.ads.RunnableFutureC2161hw;
import com.google.android.gms.internal.ads.S3;
import com.google.android.gms.internal.ads.SharedPreferencesOnSharedPreferenceChangeListenerC2687u7;
import com.google.android.gms.internal.ads.T3;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Iterator;
import java.util.Vector;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class e implements Runnable, N4 {
    public static final long p = System.currentTimeMillis();
    public boolean d;
    public final boolean e;
    public final boolean f;
    public final ExecutorService g;
    public final k h;
    public Context i;
    public final Context j;
    public VersionInfoParcel k;
    public final VersionInfoParcel l;
    public final boolean m;
    public int o;
    public final Vector a = new Vector();
    public final AtomicReference b = new AtomicReference();
    public final AtomicReference c = new AtomicReference();
    public final CountDownLatch n = new CountDownLatch(1);

    public e(Context context, VersionInfoParcel versionInfoParcel) {
        this.i = context;
        this.j = context;
        this.k = versionInfoParcel;
        this.l = versionInfoParcel;
        ExecutorService executorServiceNewCachedThreadPool = Executors.newCachedThreadPool();
        this.g = executorServiceNewCachedThreadPool;
        C2601s7 c2601s7 = AbstractC2773w7.y2;
        r rVar = r.d;
        boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
        this.m = zBooleanValue;
        this.h = k.k(context, executorServiceNewCachedThreadPool, zBooleanValue);
        C2601s7 c2601s72 = AbstractC2773w7.v2;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        this.e = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue();
        this.f = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.z2)).booleanValue();
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.x2)).booleanValue()) {
            this.o = 2;
        } else {
            this.o = 1;
        }
        if (!((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.B3)).booleanValue()) {
            this.d = k();
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.v3)).booleanValue()) {
            AbstractC2270kd.a.execute(this);
            return;
        }
        com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
        if (Looper.myLooper() == Looper.getMainLooper()) {
            AbstractC2270kd.a.execute(this);
        } else {
            run();
        }
    }

    public static final L4 p(Context context, VersionInfoParcel versionInfoParcel, boolean z, boolean z2) {
        L4 l4M;
        S3 s3W = T3.w();
        s3W.e();
        T3.A((T3) s3W.b, z);
        String str = versionInfoParcel.a;
        s3W.e();
        T3.B((T3) s3W.b, str);
        T3 t3 = (T3) s3W.c();
        Context applicationContext = context.getApplicationContext();
        if (applicationContext != null) {
            context = applicationContext;
        }
        synchronized (L4.class) {
            C2371ms c2371ms = new C2371ms();
            c2371ms.b = false;
            byte b = (byte) (c2371ms.f | 1);
            c2371ms.c = true;
            c2371ms.d = 100L;
            c2371ms.e = 300L;
            c2371ms.f = (byte) (((byte) (((byte) (((byte) (((byte) (b | 2)) | 4)) | 8)) | 16)) | 32);
            String strZ = t3.z();
            if (strZ == null) {
                throw new NullPointerException("Null clientVersion");
            }
            c2371ms.a = strZ;
            c2371ms.b = t3.C();
            c2371ms.f = (byte) (c2371ms.f | 1);
            l4M = L4.m(context, Executors.newCachedThreadPool(), c2371ms.a(), z2);
        }
        return l4M;
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final void a(View view) {
        N4 n4M = m();
        if (n4M != null) {
            n4M.a(view);
        }
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String b(Context context) {
        return j(context);
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final void c(StackTraceElement[] stackTraceElementArr) {
        N4 n4M;
        N4 n4M2;
        if (((Boolean) r.d.c.a(AbstractC2773w7.V2)).booleanValue()) {
            if (this.n.getCount() != 0 || (n4M2 = m()) == null) {
                return;
            }
            n4M2.c(stackTraceElementArr);
            return;
        }
        if (!l() || (n4M = m()) == null) {
            return;
        }
        n4M.c(stackTraceElementArr);
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String d(Context context, View view, String str) {
        return f(context, str, view, null);
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String e(Context context) {
        RunnableFutureC2161hw runnableFutureC2161hw = new RunnableFutureC2161hw(new y(this, false, context, 2));
        this.g.execute(runnableFutureC2161hw);
        try {
            return (String) runnableFutureC2161hw.get(((Integer) r.d.c.a(AbstractC2773w7.P2)).intValue(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException | ExecutionException unused) {
            return Integer.toString(17);
        } catch (TimeoutException unused2) {
            String str = this.l.a;
            long j = p;
            try {
                C2598s4 c2598s4W = C2641t4.w();
                c2598s4W.e();
                C2641t4.y((C2641t4) c2598s4W.b, str);
                c2598s4W.e();
                C2641t4.x((C2641t4) c2598s4W.b);
                String packageName = context.getPackageName();
                c2598s4W.e();
                C2641t4.z((C2641t4) c2598s4W.b, packageName);
                long jCurrentTimeMillis = (System.currentTimeMillis() - j) / 1000;
                c2598s4W.e();
                C2641t4.B((C2641t4) c2598s4W.b, jCurrentTimeMillis);
                long jCurrentTimeMillis2 = System.currentTimeMillis() / 1000;
                c2598s4W.e();
                C2641t4.A((C2641t4) c2598s4W.b, jCurrentTimeMillis2);
                try {
                    long j2 = context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionCode;
                    c2598s4W.e();
                    C2641t4.C((C2641t4) c2598s4W.b, j2);
                } catch (PackageManager.NameNotFoundException unused3) {
                    c2598s4W.e();
                    C2641t4.C((C2641t4) c2598s4W.b, -1L);
                }
                C2770w4 c2770w4A = D4.a(null, ((C2641t4) c2598s4W.c()).d());
                c2770w4A.e();
                C2813x4.A((C2813x4) c2770w4A.b);
                c2770w4A.e();
                C2813x4.z((C2813x4) c2770w4A.b, 2);
                return Base64.encodeToString(((C2813x4) c2770w4A.c()).d(), 11);
            } catch (UnsupportedEncodingException | GeneralSecurityException unused4) {
                return Integer.toString(7);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String f(Context context, String str, View view, Activity activity) {
        if (!l()) {
            return "";
        }
        N4 n4M = m();
        if (((Boolean) r.d.c.a(AbstractC2773w7.Ga)).booleanValue()) {
            F f = j.C.c;
            F.i(4, view);
        }
        if (n4M == null) {
            return "";
        }
        n();
        Context applicationContext = context.getApplicationContext();
        if (applicationContext != null) {
            context = applicationContext;
        }
        return n4M.f(context, str, view, activity);
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final void g(int i, int i2, int i3) {
        N4 n4M = m();
        if (n4M == null) {
            this.a.add(new Object[]{Integer.valueOf(i), Integer.valueOf(i2), Integer.valueOf(i3)});
        } else {
            n();
            n4M.g(i, i2, i3);
        }
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final void h(MotionEvent motionEvent) {
        N4 n4M = m();
        if (n4M == null) {
            this.a.add(new Object[]{motionEvent});
        } else {
            n();
            n4M.h(motionEvent);
        }
    }

    @Override // com.google.android.gms.internal.ads.N4
    public final String i(Context context, View view, Activity activity) {
        C2601s7 c2601s7 = AbstractC2773w7.Fa;
        r rVar = r.d;
        boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        if (!zBooleanValue) {
            N4 n4M = m();
            if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.Ga)).booleanValue()) {
                F f = j.C.c;
                F.i(2, view);
            }
            return n4M != null ? n4M.i(context, view, activity) : "";
        }
        if (!l()) {
            return "";
        }
        N4 n4M2 = m();
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.Ga)).booleanValue()) {
            F f2 = j.C.c;
            F.i(2, view);
        }
        return n4M2 != null ? n4M2.i(context, view, activity) : "";
    }

    public final String j(Context context) {
        N4 n4M;
        if (!l() || (n4M = m()) == null) {
            return "";
        }
        n();
        Context applicationContext = context.getApplicationContext();
        if (applicationContext != null) {
            context = applicationContext;
        }
        return n4M.b(context);
    }

    public final boolean k() throws IOException {
        Context context = this.i;
        Q q = new Q(this);
        Bs bs = new Bs(context, AbstractC1981ds.l(context, this.h), q, ((Boolean) r.d.c.a(AbstractC2773w7.w2)).booleanValue());
        long jCurrentTimeMillis = System.currentTimeMillis();
        synchronized (Bs.f) {
            try {
                C2728v5 c2728v5H = bs.h(1);
                if (c2728v5H == null) {
                    bs.g(4025, jCurrentTimeMillis);
                    return false;
                }
                File fileE = bs.e(c2728v5H.E());
                if (!new File(fileE, "pcam.jar").exists()) {
                    bs.g(4026, jCurrentTimeMillis);
                    return false;
                }
                if (new File(fileE, "pcbc").exists()) {
                    bs.g(5019, jCurrentTimeMillis);
                    return true;
                }
                bs.g(4027, jCurrentTimeMillis);
                return false;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final boolean l() throws InterruptedException {
        try {
            this.n.await();
            return true;
        } catch (InterruptedException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Interrupted during GADSignals creation.", e);
            return false;
        }
    }

    public final N4 m() {
        return ((!this.e || this.d) ? this.o : 1) == 2 ? (N4) this.c.get() : (N4) this.b.get();
    }

    public final void n() {
        Vector vector = this.a;
        N4 n4M = m();
        if (vector.isEmpty() || n4M == null) {
            return;
        }
        Iterator it2 = vector.iterator();
        while (it2.hasNext()) {
            Object[] objArr = (Object[]) it2.next();
            int length = objArr.length;
            if (length == 1) {
                n4M.h((MotionEvent) objArr[0]);
            } else if (length == 3) {
                n4M.g(((Integer) objArr[0]).intValue(), ((Integer) objArr[1]).intValue(), ((Integer) objArr[2]).intValue());
            }
        }
        vector.clear();
    }

    public final void o(boolean z) {
        String str = this.k.a;
        Context context = this.i;
        Context applicationContext = context.getApplicationContext();
        if (applicationContext != null) {
            context = applicationContext;
        }
        S3 s3W = T3.w();
        s3W.e();
        T3.A((T3) s3W.b, z);
        s3W.e();
        T3.B((T3) s3W.b, str);
        this.b.set(O4.u(context, new p((T3) s3W.c())));
    }

    @Override // java.lang.Runnable
    public final void run() {
        boolean z;
        try {
            C2601s7 c2601s7 = AbstractC2773w7.B3;
            r rVar = r.d;
            if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                this.d = k();
            }
            boolean z2 = this.k.d;
            boolean z3 = false;
            if (!((Boolean) rVar.c.a(AbstractC2773w7.a1)).booleanValue() && z2) {
                z3 = true;
            }
            if (((!this.e || this.d) ? this.o : 1) == 1) {
                o(z3);
                if (this.o == 2) {
                    this.g.execute(new o(z3, 2, this));
                }
            } else {
                long jCurrentTimeMillis = System.currentTimeMillis();
                try {
                    L4 l4P = p(this.i, this.k, z3, this.m);
                    this.c.set(l4P);
                    if (this.f) {
                        synchronized (l4P) {
                            z = l4P.p;
                        }
                        if (!z) {
                            this.o = 1;
                            o(z3);
                        }
                    }
                } catch (NullPointerException e) {
                    this.o = 1;
                    o(z3);
                    this.h.r(2031, System.currentTimeMillis() - jCurrentTimeMillis, e);
                }
            }
            this.n.countDown();
            this.i = null;
            this.k = null;
        } catch (Throwable th) {
            this.n.countDown();
            this.i = null;
            this.k = null;
            throw th;
        }
    }
}
