package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.view.View;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public final class Yi {
    public int a;
    public com.google.android.gms.ads.internal.client.u0 b;
    public InterfaceC2645t8 c;
    public View d;
    public List e;
    public com.google.android.gms.ads.internal.client.E0 g;
    public Bundle h;
    public InterfaceC2529qe i;
    public InterfaceC2529qe j;
    public InterfaceC2529qe k;
    public C2665tm l;
    public com.google.common.util.concurrent.e m;
    public C2313ld n;
    public View o;
    public View p;
    public com.google.android.gms.dynamic.a q;
    public double r;
    public InterfaceC2860y8 s;
    public InterfaceC2860y8 t;
    public String u;
    public float x;
    public String y;
    public final androidx.collection.V v = new androidx.collection.V(0);
    public final androidx.collection.V w = new androidx.collection.V(0);
    public List f = Collections.EMPTY_LIST;

    public static Yi e(Xi xi, InterfaceC2645t8 interfaceC2645t8, View view, String str, List list, String str2, Bundle bundle, String str3, View view2, com.google.android.gms.dynamic.a aVar, String str4, String str5, double d, InterfaceC2860y8 interfaceC2860y8, String str6, float f) {
        Yi yi = new Yi();
        yi.a = 6;
        yi.b = xi;
        yi.c = interfaceC2645t8;
        yi.d = view;
        yi.d("headline", str);
        yi.e = list;
        yi.d("body", str2);
        yi.h = bundle;
        yi.d("call_to_action", str3);
        yi.o = view2;
        yi.q = aVar;
        yi.d("store", str4);
        yi.d("price", str5);
        yi.r = d;
        yi.s = interfaceC2860y8;
        yi.d("advertiser", str6);
        synchronized (yi) {
            yi.x = f;
        }
        return yi;
    }

    public static Object f(com.google.android.gms.dynamic.a aVar) {
        if (aVar == null) {
            return null;
        }
        return com.google.android.gms.dynamic.b.I3(aVar);
    }

    public static Yi n(InterfaceC1707Ia interfaceC1707Ia) {
        Xi xi;
        InterfaceC1707Ia interfaceC1707Ia2;
        try {
            com.google.android.gms.ads.internal.client.v0 v0VarI = interfaceC1707Ia.i();
            if (v0VarI == null) {
                interfaceC1707Ia2 = interfaceC1707Ia;
                xi = null;
            } else {
                interfaceC1707Ia2 = interfaceC1707Ia;
                xi = new Xi(v0VarI, interfaceC1707Ia2);
            }
            return e(xi, interfaceC1707Ia2.n(), (View) f(interfaceC1707Ia2.l()), interfaceC1707Ia2.z(), interfaceC1707Ia2.d(), interfaceC1707Ia2.p(), interfaceC1707Ia2.zzi(), interfaceC1707Ia2.w(), (View) f(interfaceC1707Ia2.m()), interfaceC1707Ia2.x(), interfaceC1707Ia2.c(), interfaceC1707Ia2.s(), interfaceC1707Ia2.zze(), interfaceC1707Ia2.k(), interfaceC1707Ia2.o(), interfaceC1707Ia2.f());
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Failed to get native ad assets from unified ad mapper", e);
            return null;
        }
    }

    public final synchronized String a() {
        return this.u;
    }

    public final synchronized String b() {
        return c("headline");
    }

    public final synchronized String c(String str) {
        return (String) this.w.get(str);
    }

    public final synchronized void d(String str, String str2) {
        if (str2 == null) {
            this.w.remove(str);
        } else {
            this.w.put(str, str2);
        }
    }

    public final synchronized int g() {
        return this.a;
    }

    public final synchronized Bundle h() {
        try {
            if (this.h == null) {
                this.h = new Bundle();
            }
        } catch (Throwable th) {
            throw th;
        }
        return this.h;
    }

    public final synchronized com.google.android.gms.ads.internal.client.v0 i() {
        return this.b;
    }

    public final synchronized InterfaceC2645t8 j() {
        return this.c;
    }

    public final InterfaceC2860y8 k() {
        List list = this.e;
        if (list == null || list.isEmpty()) {
            return null;
        }
        Object obj = this.e.get(0);
        if (obj instanceof IBinder) {
            return BinderC2474p8.e4((IBinder) obj);
        }
        return null;
    }

    public final synchronized InterfaceC2529qe l() {
        return this.k;
    }

    public final synchronized InterfaceC2529qe m() {
        return this.i;
    }

    public final synchronized C2665tm o() {
        return this.l;
    }

    public final synchronized String p() {
        return c("advertiser");
    }

    public final synchronized String q() {
        return c("body");
    }

    public final synchronized String r() {
        return c("call_to_action");
    }
}
