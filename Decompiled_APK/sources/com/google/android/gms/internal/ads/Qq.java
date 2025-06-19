package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.IBinder;
import android.os.SystemClock;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.zze;

/* loaded from: classes2.dex */
public final class Qq implements Pq {
    public final Context a;
    public final int p;
    public long b = 0;
    public long c = -1;
    public boolean d = false;
    public int q = 2;
    public int r = 2;
    public int e = 0;
    public String f = "";
    public String g = "";
    public String h = "";
    public String i = "";
    public int j = 2;
    public String k = "";
    public String l = "";
    public String m = "";
    public boolean n = false;
    public boolean o = false;

    public Qq(Context context, int i) {
        this.a = context;
        this.p = i;
    }

    @Override // com.google.android.gms.internal.ads.Pq
    public final Pq A(String str) {
        synchronized (this) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.P8)).booleanValue()) {
                this.m = str;
            }
        }
        return this;
    }

    @Override // com.google.android.gms.internal.ads.Pq
    public final Pq I(String str) {
        synchronized (this) {
            this.h = str;
        }
        return this;
    }

    @Override // com.google.android.gms.internal.ads.Pq
    public final Pq R(String str) {
        synchronized (this) {
            this.i = str;
        }
        return this;
    }

    public final synchronized void a() {
        com.google.android.gms.ads.internal.j.C.k.getClass();
        this.c = SystemClock.elapsedRealtime();
    }

    public final synchronized void b() {
        Configuration configuration;
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        com.google.android.gms.ads.internal.util.G g = jVar.f;
        Context context = this.a;
        this.e = g.e(context);
        Resources resources = context.getResources();
        int i = 2;
        if (resources != null && (configuration = resources.getConfiguration()) != null) {
            i = configuration.orientation == 2 ? 4 : 3;
        }
        this.r = i;
        jVar.k.getClass();
        this.b = SystemClock.elapsedRealtime();
        this.o = true;
    }

    @Override // com.google.android.gms.internal.ads.Pq
    public final Pq d(int i) {
        synchronized (this) {
            this.j = i;
        }
        return this;
    }

    @Override // com.google.android.gms.internal.ads.Pq
    public final Pq e(int i) {
        synchronized (this) {
            this.q = i;
        }
        return this;
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x002e, code lost:
    
        r2.g = r0;
     */
    @Override // com.google.android.gms.internal.ads.Pq
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.ads.Pq f(androidx.work.impl.model.n r3) {
        /*
            r2 = this;
            monitor-enter(r2)
            java.lang.Object r0 = r3.b     // Catch: java.lang.Throwable -> L10
            com.google.android.gms.internal.ads.Xp r0 = (com.google.android.gms.internal.ads.Xp) r0     // Catch: java.lang.Throwable -> L10
            java.lang.String r0 = r0.b     // Catch: java.lang.Throwable -> L10
            boolean r1 = android.text.TextUtils.isEmpty(r0)     // Catch: java.lang.Throwable -> L10
            if (r1 != 0) goto L12
            r2.f = r0     // Catch: java.lang.Throwable -> L10
            goto L12
        L10:
            r3 = move-exception
            goto L32
        L12:
            java.lang.Object r3 = r3.a     // Catch: java.lang.Throwable -> L10
            java.util.List r3 = (java.util.List) r3     // Catch: java.lang.Throwable -> L10
            java.util.Iterator r3 = r3.iterator()     // Catch: java.lang.Throwable -> L10
        L1a:
            boolean r0 = r3.hasNext()     // Catch: java.lang.Throwable -> L10
            if (r0 == 0) goto L30
            java.lang.Object r0 = r3.next()     // Catch: java.lang.Throwable -> L10
            com.google.android.gms.internal.ads.Vp r0 = (com.google.android.gms.internal.ads.Vp) r0     // Catch: java.lang.Throwable -> L10
            java.lang.String r0 = r0.b0     // Catch: java.lang.Throwable -> L10
            boolean r1 = android.text.TextUtils.isEmpty(r0)     // Catch: java.lang.Throwable -> L10
            if (r1 != 0) goto L1a
            r2.g = r0     // Catch: java.lang.Throwable -> L10
        L30:
            monitor-exit(r2)
            return r2
        L32:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L10
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Qq.f(androidx.work.impl.model.n):com.google.android.gms.internal.ads.Pq");
    }

    @Override // com.google.android.gms.internal.ads.Pq
    public final Pq g(Throwable th) {
        synchronized (this) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.P8)).booleanValue()) {
                String strA = com.google.android.gms.ads.internal.util.client.c.a(C1744Ob.f(th), "SHA-256");
                if (strA == null) {
                    strA = "";
                }
                this.l = strA;
                String strF = C1744Ob.f(th);
                C2883yp c2883ypE = C2883yp.e(new C2501pt('\n'));
                strF.getClass();
                this.k = (String) ((AbstractC2930zt) ((At) c2883ypE.b).e(c2883ypE, strF)).next();
            }
        }
        return this;
    }

    @Override // com.google.android.gms.internal.ads.Pq
    public final Pq h(boolean z) {
        synchronized (this) {
            this.d = z;
        }
        return this;
    }

    @Override // com.google.android.gms.internal.ads.Pq
    public final /* bridge */ /* synthetic */ Pq i() {
        a();
        return this;
    }

    @Override // com.google.android.gms.internal.ads.Pq
    public final Pq j(zze zzeVar) {
        synchronized (this) {
            try {
                IBinder iBinder = zzeVar.e;
                if (iBinder != null) {
                    Ug ug = (Ug) iBinder;
                    String str = ug.d;
                    if (!TextUtils.isEmpty(str)) {
                        this.f = str;
                    }
                    String str2 = ug.b;
                    if (!TextUtils.isEmpty(str2)) {
                        this.g = str2;
                    }
                }
            } finally {
            }
        }
        return this;
    }

    @Override // com.google.android.gms.internal.ads.Pq
    public final boolean k() {
        return !TextUtils.isEmpty(this.h);
    }

    @Override // com.google.android.gms.internal.ads.Pq
    public final synchronized Rq l() {
        try {
            if (this.n) {
                return null;
            }
            this.n = true;
            if (!this.o) {
                b();
            }
            if (this.c < 0) {
                a();
            }
            return new Rq(this);
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pq
    public final synchronized boolean n() {
        return this.o;
    }

    @Override // com.google.android.gms.internal.ads.Pq
    public final /* bridge */ /* synthetic */ Pq zzi() {
        b();
        return this;
    }
}
