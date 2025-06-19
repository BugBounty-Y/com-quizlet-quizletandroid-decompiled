package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Pair;
import com.google.android.gms.measurement.internal.InterfaceC3897v;
import com.google.android.gms.measurement.internal.zzqb;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final /* synthetic */ class BD implements Runnable {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    public /* synthetic */ BD(DD dd, Pair pair, YE ye, androidx.compose.animation.core.S0 s0, IOException iOException, boolean z) {
        this.c = dd;
        this.d = pair;
        this.e = ye;
        this.f = s0;
        this.g = iOException;
        this.b = z;
    }

    @Override // java.lang.Runnable
    public final void run() throws Throwable {
        com.google.android.gms.measurement.internal.x1 x1Var;
        InterfaceC3897v interfaceC3897v;
        String str;
        AtomicReference atomicReference;
        com.google.android.gms.measurement.internal.Y0 y0;
        InterfaceC3897v interfaceC3897v2;
        switch (this.a) {
            case 0:
                WD wd = (WD) ((DD) this.c).b.i;
                Pair pair = (Pair) this.d;
                wd.a(((Integer) pair.first).intValue(), (C2093gF) pair.second, (YE) this.e, (androidx.compose.animation.core.S0) this.f, (IOException) this.g, this.b);
                return;
            case 1:
                String str2 = (String) this.c;
                com.google.android.gms.internal.measurement.L l = (com.google.android.gms.internal.measurement.L) this.f;
                com.google.android.gms.measurement.internal.Y0 y02 = (com.google.android.gms.measurement.internal.Y0) this.g;
                com.google.android.gms.measurement.internal.Y y = (com.google.android.gms.measurement.internal.Y) y02.b;
                Bundle bundle = new Bundle();
                try {
                    try {
                        interfaceC3897v = y02.e;
                        str = (String) this.d;
                    } catch (RemoteException e) {
                        e = e;
                    }
                    if (interfaceC3897v == null) {
                        com.google.android.gms.measurement.internal.I i = y.i;
                        com.google.android.gms.measurement.internal.Y.k(i);
                        i.g.h("Failed to get user properties; not connected to service", str2, str);
                        x1Var = y.l;
                        com.google.android.gms.measurement.internal.Y.h(x1Var);
                        x1Var.p0(l, bundle);
                        return;
                    }
                    List<zzqb> listP0 = interfaceC3897v.P0(str2, str, this.b, (com.google.android.gms.measurement.internal.zzr) this.e);
                    Bundle bundle2 = new Bundle();
                    if (listP0 != null) {
                        for (zzqb zzqbVar : listP0) {
                            String str3 = zzqbVar.e;
                            String str4 = zzqbVar.b;
                            if (str3 != null) {
                                bundle2.putString(str4, str3);
                            } else {
                                Long l2 = zzqbVar.d;
                                if (l2 != null) {
                                    bundle2.putLong(str4, l2.longValue());
                                } else {
                                    Double d = zzqbVar.g;
                                    if (d != null) {
                                        bundle2.putDouble(str4, d.doubleValue());
                                    }
                                }
                            }
                        }
                    }
                    try {
                        y02.h0();
                        com.google.android.gms.measurement.internal.x1 x1Var2 = y.l;
                        com.google.android.gms.measurement.internal.Y.h(x1Var2);
                        x1Var2.p0(l, bundle2);
                        return;
                    } catch (RemoteException e2) {
                        e = e2;
                        bundle = bundle2;
                        com.google.android.gms.measurement.internal.I i2 = y.i;
                        com.google.android.gms.measurement.internal.Y.k(i2);
                        i2.g.h("Failed to get user properties; remote exception", str2, e);
                        x1Var = y.l;
                        com.google.android.gms.measurement.internal.Y.h(x1Var);
                        x1Var.p0(l, bundle);
                        return;
                    } catch (Throwable th) {
                        th = th;
                        bundle = bundle2;
                        com.google.android.gms.measurement.internal.x1 x1Var3 = y.l;
                        com.google.android.gms.measurement.internal.Y.h(x1Var3);
                        x1Var3.p0(l, bundle);
                        throw th;
                    }
                } catch (Throwable th2) {
                    th = th2;
                }
            default:
                AtomicReference atomicReference2 = (AtomicReference) this.c;
                synchronized (atomicReference2) {
                    try {
                        try {
                            y0 = (com.google.android.gms.measurement.internal.Y0) this.g;
                            interfaceC3897v2 = y0.e;
                        } catch (RemoteException e3) {
                            com.google.android.gms.measurement.internal.I i3 = ((com.google.android.gms.measurement.internal.Y) ((com.google.android.gms.measurement.internal.Y0) this.g).b).i;
                            com.google.android.gms.measurement.internal.Y.k(i3);
                            i3.g.i("(legacy) Failed to get user properties; remote exception", null, (String) this.d, e3);
                            ((AtomicReference) this.c).set(Collections.EMPTY_LIST);
                            atomicReference = (AtomicReference) this.c;
                        }
                        if (interfaceC3897v2 == null) {
                            com.google.android.gms.measurement.internal.I i4 = ((com.google.android.gms.measurement.internal.Y) y0.b).i;
                            com.google.android.gms.measurement.internal.Y.k(i4);
                            i4.g.i("(legacy) Failed to get user properties; not connected to service", null, (String) this.d, (String) this.e);
                            atomicReference2.set(Collections.EMPTY_LIST);
                            atomicReference2.notify();
                            return;
                        }
                        if (TextUtils.isEmpty(null)) {
                            atomicReference2.set(interfaceC3897v2.P0((String) this.d, (String) this.e, this.b, (com.google.android.gms.measurement.internal.zzr) this.f));
                        } else {
                            atomicReference2.set(interfaceC3897v2.Y1(null, (String) this.d, (String) this.e, this.b));
                        }
                        y0.h0();
                        atomicReference = (AtomicReference) this.c;
                        atomicReference.notify();
                        return;
                    } catch (Throwable th3) {
                        ((AtomicReference) this.c).notify();
                        throw th3;
                    }
                }
        }
    }

    public BD(com.google.android.gms.measurement.internal.Y0 y0, String str, String str2, com.google.android.gms.measurement.internal.zzr zzrVar, boolean z, com.google.android.gms.internal.measurement.L l) {
        this.c = str;
        this.d = str2;
        this.e = zzrVar;
        this.b = z;
        this.f = l;
        this.g = y0;
    }

    public BD(com.google.android.gms.measurement.internal.Y0 y0, AtomicReference atomicReference, String str, String str2, com.google.android.gms.measurement.internal.zzr zzrVar, boolean z) {
        this.c = atomicReference;
        this.d = str;
        this.e = str2;
        this.f = zzrVar;
        this.b = z;
        this.g = y0;
    }
}
