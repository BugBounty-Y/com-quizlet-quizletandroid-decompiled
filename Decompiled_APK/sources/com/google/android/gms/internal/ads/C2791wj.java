package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import android.os.Parcel;
import android.os.RemoteException;
import android.view.MotionEvent;
import android.view.View;
import android.widget.ImageView;
import com.google.android.gms.ads.internal.client.C1591e0;
import com.google.android.gms.ads.internal.client.InterfaceC1595g0;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.wj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2791wj implements InterfaceC1886bj {
    public final InterfaceC1707Ia a;
    public final C2146hh b;
    public final Vg c;
    public final C2404ni d;
    public final Context e;
    public final Vp f;
    public final VersionInfoParcel g;
    public final C2023eq h;
    public boolean i = false;
    public boolean j = false;
    public boolean k = true;
    public final C1683Ea l;
    public final C1689Fa m;

    public C2791wj(C1683Ea c1683Ea, C1689Fa c1689Fa, InterfaceC1707Ia interfaceC1707Ia, C2146hh c2146hh, Vg vg, C2404ni c2404ni, Context context, Vp vp, VersionInfoParcel versionInfoParcel, C2023eq c2023eq) {
        this.l = c1683Ea;
        this.m = c1689Fa;
        this.a = interfaceC1707Ia;
        this.b = c2146hh;
        this.c = vg;
        this.d = c2404ni;
        this.e = context;
        this.f = vp;
        this.g = versionInfoParcel;
        this.h = c2023eq;
    }

    public static final HashMap v(Map map) {
        HashMap map2 = new HashMap();
        if (map == null) {
            return map2;
        }
        synchronized (map) {
            try {
                for (Map.Entry entry : map.entrySet()) {
                    View view = (View) ((WeakReference) entry.getValue()).get();
                    if (view != null) {
                        map2.put((String) entry.getKey(), view);
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return map2;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void B() {
        this.j = true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final boolean J() {
        return this.f.L;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void T(String str) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void a(View view, Map map, Map map2, ImageView.ScaleType scaleType) {
    }

    /* JADX WARN: Removed duplicated region for block: B:48:0x00d3 A[Catch: RemoteException -> 0x0032, JSONException -> 0x0050, TRY_LEAVE, TryCatch #0 {RemoteException -> 0x0032, blocks: (B:2:0x0000, B:5:0x0022, B:9:0x002c, B:14:0x0039, B:16:0x0041, B:17:0x0050, B:19:0x0056, B:21:0x0062, B:24:0x006e, B:27:0x0075, B:29:0x008b, B:41:0x00ac, B:44:0x00b3, B:45:0x00b7, B:46:0x00cd, B:48:0x00d3, B:52:0x00e5, B:54:0x00f1, B:57:0x0103, B:59:0x012c), top: B:66:0x0000 }] */
    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(android.view.View r14, java.util.Map r15, java.util.Map r16, com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj r17, com.google.android.gms.internal.ads.InterfaceViewOnClickListenerC2705uj r18) throws java.lang.SecurityException {
        /*
            Method dump skipped, instructions count: 345
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2791wj.b(android.view.View, java.util.Map, java.util.Map, com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.uj):void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void c() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void d(Bundle bundle) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final boolean e() {
        return true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void f(View view) {
        try {
            com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(view);
            InterfaceC1707Ia interfaceC1707Ia = this.a;
            if (interfaceC1707Ia != null) {
                interfaceC1707Ia.y1(bVar);
                return;
            }
            C1683Ea c1683Ea = this.l;
            if (c1683Ea != null) {
                Parcel parcelF3 = c1683Ea.f3();
                AbstractC2857y5.e(parcelF3, bVar);
                c1683Ea.d4(16, parcelF3);
            } else {
                C1689Fa c1689Fa = this.m;
                if (c1689Fa != null) {
                    Parcel parcelF32 = c1689Fa.f3();
                    AbstractC2857y5.e(parcelF32, bVar);
                    c1689Fa.d4(14, parcelF32);
                }
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Failed to call untrackView", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void g(Bundle bundle) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void h(View view, Map map, Map map2, ImageView.ScaleType scaleType) {
        try {
            if (!this.i) {
                this.i = com.google.android.gms.ads.internal.j.C.o.i(this.e, this.g.a, this.f.C.toString(), this.h.f);
            }
            if (this.k) {
                InterfaceC1707Ia interfaceC1707Ia = this.a;
                C2146hh c2146hh = this.b;
                if (interfaceC1707Ia != null && !interfaceC1707Ia.K()) {
                    interfaceC1707Ia.y();
                    c2146hh.a();
                    return;
                }
                C1683Ea c1683Ea = this.l;
                if (c1683Ea != null) {
                    Parcel parcelY3 = c1683Ea.Y3(13, c1683Ea.f3());
                    ClassLoader classLoader = AbstractC2857y5.a;
                    boolean z = parcelY3.readInt() != 0;
                    parcelY3.recycle();
                    if (!z) {
                        c1683Ea.d4(10, c1683Ea.f3());
                        c2146hh.a();
                        return;
                    }
                }
                C1689Fa c1689Fa = this.m;
                if (c1689Fa != null) {
                    Parcel parcelY32 = c1689Fa.Y3(11, c1689Fa.f3());
                    ClassLoader classLoader2 = AbstractC2857y5.a;
                    boolean z2 = parcelY32.readInt() != 0;
                    parcelY32.recycle();
                    if (z2) {
                        return;
                    }
                    c1689Fa.d4(8, c1689Fa.f3());
                    c2146hh.a();
                }
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Failed to call recordImpression", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void i() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void j(View view, View view2, Map map, Map map2, boolean z, ImageView.ScaleType scaleType, int i) {
        if (!this.j) {
            com.google.android.gms.ads.internal.util.client.i.h("Custom click reporting for 3p ads failed. enableCustomClickGesture is not set.");
        } else if (this.f.L) {
            u(view2);
        } else {
            com.google.android.gms.ads.internal.util.client.i.h("Custom click reporting for 3p ads failed. Ad unit id not in allow list.");
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void k(View view, MotionEvent motionEvent) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void l(V8 v8) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void m(View view, View view2, Map map, Map map2, boolean z, ImageView.ScaleType scaleType) {
        if (this.j && this.f.L) {
            return;
        }
        u(view);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void n() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final JSONObject o(View view, Map map, Map map2, ImageView.ScaleType scaleType) {
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void p(View view) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void q(InterfaceC1595g0 interfaceC1595g0) {
        com.google.android.gms.ads.internal.util.client.i.h("Mute This Ad is not supported for 3rd party ads");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final boolean r(Bundle bundle) {
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final JSONObject s(View view, Map map, Map map2, ImageView.ScaleType scaleType) {
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void t(C1591e0 c1591e0) {
        com.google.android.gms.ads.internal.util.client.i.h("Mute This Ad is not supported for 3rd party ads");
    }

    public final void u(View view) {
        try {
            InterfaceC1707Ia interfaceC1707Ia = this.a;
            C2404ni c2404ni = this.d;
            Vg vg = this.c;
            if (interfaceC1707Ia != null && !interfaceC1707Ia.j0()) {
                interfaceC1707Ia.u0(new com.google.android.gms.dynamic.b(view));
                vg.onAdClicked();
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.La)).booleanValue()) {
                    c2404ni.c0();
                    return;
                }
                return;
            }
            C1683Ea c1683Ea = this.l;
            if (c1683Ea != null) {
                Parcel parcelY3 = c1683Ea.Y3(14, c1683Ea.f3());
                ClassLoader classLoader = AbstractC2857y5.a;
                boolean z = parcelY3.readInt() != 0;
                parcelY3.recycle();
                if (!z) {
                    com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(view);
                    Parcel parcelF3 = c1683Ea.f3();
                    AbstractC2857y5.e(parcelF3, bVar);
                    c1683Ea.d4(11, parcelF3);
                    vg.onAdClicked();
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.La)).booleanValue()) {
                        c2404ni.c0();
                        return;
                    }
                    return;
                }
            }
            C1689Fa c1689Fa = this.m;
            if (c1689Fa != null) {
                Parcel parcelY32 = c1689Fa.Y3(12, c1689Fa.f3());
                ClassLoader classLoader2 = AbstractC2857y5.a;
                boolean z2 = parcelY32.readInt() != 0;
                parcelY32.recycle();
                if (z2) {
                    return;
                }
                com.google.android.gms.dynamic.b bVar2 = new com.google.android.gms.dynamic.b(view);
                Parcel parcelF32 = c1689Fa.f3();
                AbstractC2857y5.e(parcelF32, bVar2);
                c1689Fa.d4(9, parcelF32);
                vg.onAdClicked();
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.La)).booleanValue()) {
                    c2404ni.c0();
                }
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Failed to call handleClick", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final void z() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1886bj
    public final int zza() {
        return 0;
    }
}
