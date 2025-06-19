package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import androidx.collection.C0208f;
import com.google.android.gms.ads.internal.client.zzfw;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.ze, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2915ze extends com.google.android.gms.ads.internal.client.u0 {
    public final InterfaceC2529qe a;
    public final boolean c;
    public final boolean d;
    public int e;
    public com.google.android.gms.ads.internal.client.w0 f;
    public boolean g;
    public float i;
    public float j;
    public float k;
    public boolean l;
    public boolean m;
    public Q8 n;
    public final Object b = new Object();
    public boolean h = true;

    public BinderC2915ze(InterfaceC2529qe interfaceC2529qe, float f, boolean z, boolean z2) {
        this.a = interfaceC2529qe;
        this.i = f;
        this.c = z;
        this.d = z2;
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final void E(boolean z) {
        h4(true != z ? "unmute" : "mute", null);
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final void e2(com.google.android.gms.ads.internal.client.w0 w0Var) {
        synchronized (this.b) {
            this.f = w0Var;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final float f() {
        float f;
        synchronized (this.b) {
            f = this.j;
        }
        return f;
    }

    public final void f4(float f, float f2, int i, boolean z, float f3) {
        boolean z2;
        boolean z3;
        int i2;
        synchronized (this.b) {
            try {
                z2 = true;
                if (f2 == this.i && f3 == this.k) {
                    z2 = false;
                }
                this.i = f2;
                if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Kc)).booleanValue()) {
                    this.j = f;
                }
                z3 = this.h;
                this.h = z;
                i2 = this.e;
                this.e = i;
                float f4 = this.k;
                this.k = f3;
                if (Math.abs(f3 - f4) > 1.0E-4f) {
                    this.a.N().invalidate();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (z2) {
            try {
                Q8 q8 = this.n;
                if (q8 != null) {
                    q8.d4(2, q8.f3());
                }
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
        AbstractC2270kd.f.execute(new RunnableC2872ye(this, i2, i, z3, z));
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final int g() {
        int i;
        synchronized (this.b) {
            i = this.e;
        }
        return i;
    }

    public final void g4(zzfw zzfwVar) {
        Object obj = this.b;
        boolean z = zzfwVar.b;
        boolean z2 = zzfwVar.c;
        synchronized (obj) {
            this.l = z;
            this.m = z2;
        }
        boolean z3 = zzfwVar.a;
        String str = true != z ? "0" : "1";
        String str2 = true != z2 ? "0" : "1";
        String str3 = true != z3 ? "0" : "1";
        C0208f c0208f = new C0208f(3);
        c0208f.put("muteStart", str3);
        c0208f.put("customControlsRequested", str);
        c0208f.put("clickToExpandRequested", str2);
        h4("initialState", Collections.unmodifiableMap(c0208f));
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final float h() {
        float f;
        synchronized (this.b) {
            f = this.i;
        }
        return f;
    }

    public final void h4(String str, Map map) {
        HashMap map2 = map == null ? new HashMap() : new HashMap(map);
        map2.put("action", str);
        AbstractC2270kd.f.execute(new Qv(18, this, map2));
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final void k() {
        h4("play", null);
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final void m() {
        h4("stop", null);
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final boolean o() {
        boolean z;
        synchronized (this.b) {
            try {
                z = false;
                if (this.c && this.l) {
                    z = true;
                }
            } finally {
            }
        }
        return z;
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final boolean p() {
        boolean z;
        synchronized (this.b) {
            z = this.h;
        }
        return z;
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final void t() {
        h4("pause", null);
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final boolean x() {
        boolean z;
        Object obj = this.b;
        boolean zO = o();
        synchronized (obj) {
            z = false;
            if (!zO) {
                try {
                    if (this.m && this.d) {
                        z = true;
                    }
                } finally {
                }
            }
        }
        return z;
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final float zze() {
        float f;
        synchronized (this.b) {
            f = this.k;
        }
        return f;
    }

    @Override // com.google.android.gms.ads.internal.client.v0
    public final com.google.android.gms.ads.internal.client.w0 zzi() {
        com.google.android.gms.ads.internal.client.w0 w0Var;
        synchronized (this.b) {
            w0Var = this.f;
        }
        return w0Var;
    }
}
