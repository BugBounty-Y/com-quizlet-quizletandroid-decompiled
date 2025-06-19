package com.google.android.gms.measurement;

import android.os.Bundle;
import android.os.SystemClock;
import androidx.appcompat.view.menu.RunnableC0069f;
import androidx.collection.C0208f;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.measurement.internal.C3884o;
import com.google.android.gms.measurement.internal.D0;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.InterfaceC3885o0;
import com.google.android.gms.measurement.internal.InterfaceC3887p0;
import com.google.android.gms.measurement.internal.L0;
import com.google.android.gms.measurement.internal.O0;
import com.google.android.gms.measurement.internal.RunnableC3896u0;
import com.google.android.gms.measurement.internal.RunnableC3906z0;
import com.google.android.gms.measurement.internal.X;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.measurement.internal.x1;
import com.google.android.gms.measurement.internal.zzqb;
import com.google.android.material.shape.e;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class a extends c {
    public final Y a;
    public final D0 b;

    public a(Y y) {
        u.h(y);
        this.a = y;
        D0 d0 = y.p;
        Y.j(d0);
        this.b = d0;
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void a(InterfaceC3887p0 interfaceC3887p0) {
        this.b.g0(interfaceC3887p0);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final List b(String str, String str2) {
        D0 d0 = this.b;
        Y y = (Y) d0.b;
        X x = y.j;
        Y.k(x);
        boolean zE0 = x.e0();
        I i = y.i;
        if (zE0) {
            Y.k(i);
            i.g.f("Cannot get conditional user properties from analytics worker thread");
            return new ArrayList(0);
        }
        if (e.x()) {
            Y.k(i);
            i.g.f("Cannot get conditional user properties from main thread");
            return new ArrayList(0);
        }
        AtomicReference atomicReference = new AtomicReference();
        X x2 = y.j;
        Y.k(x2);
        x2.X(atomicReference, 5000L, "get conditional user properties", new RunnableC0069f(d0, atomicReference, str, str2, 17));
        List list = (List) atomicReference.get();
        if (list != null) {
            return x1.e0(list);
        }
        Y.k(i);
        i.g.g("Timed out waiting for get conditional user properties", null);
        return new ArrayList();
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final Map c(String str, String str2, boolean z) {
        D0 d0 = this.b;
        Y y = (Y) d0.b;
        X x = y.j;
        Y.k(x);
        boolean zE0 = x.e0();
        I i = y.i;
        if (zE0) {
            Y.k(i);
            i.g.f("Cannot get user properties from analytics worker thread");
            return Collections.EMPTY_MAP;
        }
        if (e.x()) {
            Y.k(i);
            i.g.f("Cannot get user properties from main thread");
            return Collections.EMPTY_MAP;
        }
        AtomicReference atomicReference = new AtomicReference();
        X x2 = y.j;
        Y.k(x2);
        x2.X(atomicReference, 5000L, "get user properties", new RunnableC3906z0(d0, atomicReference, str, str2, z, 1));
        List<zzqb> list = (List) atomicReference.get();
        if (list == null) {
            Y.k(i);
            i.g.g("Timed out waiting for handle get user properties, includeInternal", Boolean.valueOf(z));
            return Collections.EMPTY_MAP;
        }
        C0208f c0208f = new C0208f(list.size());
        for (zzqb zzqbVar : list) {
            Object objA = zzqbVar.a();
            if (objA != null) {
                c0208f.put(zzqbVar.b, objA);
            }
        }
        return c0208f;
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void c0(String str) {
        Y y = this.a;
        C3884o c3884o = y.q;
        Y.g(c3884o);
        y.n.getClass();
        c3884o.U(SystemClock.elapsedRealtime(), str);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void d(String str, String str2, Bundle bundle, long j) {
        this.b.b0(str, str2, bundle, true, false, j);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void e(Bundle bundle) {
        D0 d0 = this.b;
        ((Y) d0.b).n.getClass();
        d0.h0(bundle, System.currentTimeMillis());
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void f(String str, String str2, Bundle bundle) {
        D0 d0 = this.b;
        ((Y) d0.b).n.getClass();
        d0.b0(str, str2, bundle, true, true, System.currentTimeMillis());
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final String g() {
        return (String) this.b.h.get();
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void h(String str) {
        Y y = this.a;
        C3884o c3884o = y.q;
        Y.g(c3884o);
        y.n.getClass();
        c3884o.T(SystemClock.elapsedRealtime(), str);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final String i() {
        O0 o0 = ((Y) this.b.b).o;
        Y.j(o0);
        L0 l0 = o0.d;
        if (l0 != null) {
            return l0.a;
        }
        return null;
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void j(String str, String str2, Bundle bundle) {
        D0 d0 = this.a.p;
        Y.j(d0);
        d0.X(str, str2, bundle);
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final void k(InterfaceC3885o0 interfaceC3885o0) {
        this.b.k0(interfaceC3885o0);
    }

    @Override // com.google.android.gms.measurement.c
    public final Map l() {
        List<zzqb> list;
        D0 d0 = this.b;
        d0.Q();
        Y y = (Y) d0.b;
        I i = y.i;
        Y.k(i);
        i.o.f("Getting user properties (FE)");
        X x = y.j;
        Y.k(x);
        boolean zE0 = x.e0();
        I i2 = y.i;
        if (zE0) {
            Y.k(i2);
            i2.g.f("Cannot get all user properties from analytics worker thread");
            list = Collections.EMPTY_LIST;
        } else if (e.x()) {
            Y.k(i2);
            i2.g.f("Cannot get all user properties from main thread");
            list = Collections.EMPTY_LIST;
        } else {
            AtomicReference atomicReference = new AtomicReference();
            Y.k(x);
            x.X(atomicReference, 5000L, "get user properties", new RunnableC3896u0(d0, atomicReference, 1));
            list = (List) atomicReference.get();
            if (list == null) {
                Y.k(i2);
                i2.g.g("Timed out waiting for get user properties, includeInternal", Boolean.TRUE);
                list = Collections.EMPTY_LIST;
            }
        }
        C0208f c0208f = new C0208f(list.size());
        for (zzqb zzqbVar : list) {
            Object objA = zzqbVar.a();
            if (objA != null) {
                c0208f.put(zzqbVar.b, objA);
            }
        }
        return c0208f;
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final String n() {
        return (String) this.b.h.get();
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final int zza(String str) {
        D0 d0 = this.b;
        d0.getClass();
        u.e(str);
        ((Y) d0.b).getClass();
        return 25;
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final long zzb() {
        x1 x1Var = this.a.l;
        Y.h(x1Var);
        return x1Var.b1();
    }

    @Override // com.google.android.gms.measurement.internal.E0
    public final String zzi() {
        O0 o0 = ((Y) this.b.b).o;
        Y.j(o0);
        L0 l0 = o0.d;
        if (l0 != null) {
            return l0.b;
        }
        return null;
    }
}
