package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.SystemClock;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.AbstractBinderC1583a0;
import com.google.android.gms.ads.internal.client.InterfaceC1603k0;
import com.google.android.gms.ads.internal.client.zzfr;
import com.google.android.gms.ads.internal.util.C1625a;
import com.google.android.gms.ads.internal.util.C1633i;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.io.IOException;
import java.util.List;
import org.json.JSONException;

/* renamed from: com.google.android.gms.internal.ads.hf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2144hf extends AbstractBinderC1583a0 {
    public static final /* synthetic */ int q = 0;
    public final Context a;
    public final VersionInfoParcel b;
    public final C2663tk c;
    public final InterfaceC2837xm d;
    public final Cn e;
    public final C1931cl f;
    public final C1739Nc g;
    public final C2749vk h;
    public final C2493pl i;
    public final C2302l8 j;
    public final Uq k;
    public final C2326lq l;
    public final Eg m;
    public final Hk n;
    public boolean o = false;
    public final Long p;

    public BinderC2144hf(Context context, VersionInfoParcel versionInfoParcel, C2663tk c2663tk, InterfaceC2837xm interfaceC2837xm, Cn cn, C1931cl c1931cl, C1739Nc c1739Nc, C2749vk c2749vk, C2493pl c2493pl, C2302l8 c2302l8, Uq uq, C2326lq c2326lq, Eg eg, Hk hk) {
        this.a = context;
        this.b = versionInfoParcel;
        this.c = c2663tk;
        this.d = interfaceC2837xm;
        this.e = cn;
        this.f = c1931cl;
        this.g = c1739Nc;
        this.h = c2749vk;
        this.i = c2493pl;
        this.j = c2302l8;
        this.k = uq;
        this.l = c2326lq;
        this.m = eg;
        this.n = hk;
        com.google.android.gms.ads.internal.j.C.k.getClass();
        this.p = Long.valueOf(SystemClock.elapsedRealtime());
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void E(boolean z) throws IOException, RemoteException {
        try {
            Context context = this.a;
            Os.e(context).k(z);
            if (z) {
                return;
            }
            try {
                if (context.getSharedPreferences("query_info_shared_prefs", 0).edit().clear().commit()) {
                } else {
                    throw new IOException("Failed to remove query_info_shared_prefs");
                }
            } catch (IOException e) {
                com.google.android.gms.ads.internal.j.C.h.h("clearStorageOnGpidPubDisable_scar", e);
            }
        } catch (IOException e2) {
            throw new RemoteException(e2.getMessage());
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void F1(InterfaceC2825xa interfaceC2825xa) {
        this.l.z(interfaceC2825xa);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void M(String str) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.u9)).booleanValue()) {
            com.google.android.gms.ads.internal.j.C.h.g = str;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void N3(K9 k9) {
        C1931cl c1931cl = this.f;
        c1931cl.getClass();
        c1931cl.e.a.a(new Qv(27, c1931cl, k9), c1931cl.j);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final synchronized void b4(boolean z) {
        C1625a c1625a = com.google.android.gms.ads.internal.j.C.i;
        synchronized (c1625a) {
            c1625a.a = z;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final synchronized void c0(String str) {
        Context context = this.a;
        AbstractC2773w7.a(context);
        if (!TextUtils.isEmpty(str)) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.c4)).booleanValue()) {
                com.google.android.gms.ads.internal.j.C.l.I(context, this.b, true, null, str, null, null, this.k, null, null, this.i.f());
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final synchronized boolean d() {
        boolean z;
        C1625a c1625a = com.google.android.gms.ads.internal.j.C.i;
        synchronized (c1625a) {
            z = c1625a.a;
        }
        return z;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final String f() {
        return this.b.a;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final List h() {
        return this.f.a();
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final synchronized void i2(float f) {
        C1625a c1625a = com.google.android.gms.ads.internal.j.C.i;
        synchronized (c1625a) {
            c1625a.b = f;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void q2(String str) {
        this.e.b(str);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void q3(com.google.android.gms.dynamic.a aVar, String str) throws JSONException {
        String strG;
        RunnableC2012ef runnableC2012ef;
        Context context = this.a;
        AbstractC2773w7.a(context);
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.j4)).booleanValue()) {
            try {
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                strG = com.google.android.gms.ads.internal.util.F.G(context);
            } catch (RemoteException | RuntimeException e) {
                com.google.android.gms.ads.internal.j.C.h.h("NonagonMobileAdsSettingManager_AppId", e);
            }
        } else {
            strG = "";
        }
        boolean z = true;
        String str2 = true == TextUtils.isEmpty(strG) ? str : strG;
        if (TextUtils.isEmpty(str2)) {
            return;
        }
        C2601s7 c2601s7 = AbstractC2773w7.c4;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
        C2601s7 c2601s72 = AbstractC2773w7.V0;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        boolean zBooleanValue2 = zBooleanValue | ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue();
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue()) {
            runnableC2012ef = new RunnableC2012ef(this, (Runnable) com.google.android.gms.dynamic.b.I3(aVar), 1);
        } else {
            runnableC2012ef = null;
            z = zBooleanValue2;
        }
        RunnableC2012ef runnableC2012ef2 = runnableC2012ef;
        if (z) {
            com.google.android.gms.ads.internal.j.C.l.I(this.a, this.b, true, null, str2, null, runnableC2012ef2, this.k, this.n, this.p, this.i.f());
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void r0(zzfr zzfrVar) {
        C1739Nc c1739Nc = this.g;
        Context context = this.a;
        c1739Nc.getClass();
        C1721Kc c1721KcI = C1721Kc.i(context);
        ((C1697Gc) ((BC) c1721KcI.d).zzb()).a(-1, ((com.google.android.gms.common.util.b) c1721KcI.b).currentTimeMillis());
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.v0)).booleanValue() && c1739Nc.e(context) && C1739Nc.g(context)) {
            synchronized (c1739Nc.i) {
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final synchronized void t() {
        if (this.o) {
            com.google.android.gms.ads.internal.util.client.i.h("Mobile ads is initialized already.");
            return;
        }
        Context context = this.a;
        AbstractC2773w7.a(context);
        VersionInfoParcel versionInfoParcel = this.b;
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        jVar.h.f(context, versionInfoParcel);
        this.m.c();
        jVar.j.s(context);
        this.o = true;
        this.f.b();
        Cn cn = this.e;
        cn.getClass();
        com.google.android.gms.ads.internal.util.C cD = jVar.h.d();
        cD.c.add(new Bn(cn, 1));
        cn.f.execute(new Bn(cn, 0));
        C2601s7 c2601s7 = AbstractC2773w7.e4;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            C2749vk c2749vk = this.h;
            if (!c2749vk.f.getAndSet(true)) {
                com.google.android.gms.ads.internal.util.C cD2 = jVar.h.d();
                cD2.c.add(new RunnableC2706uk(c2749vk, 1));
            }
            c2749vk.c.execute(new RunnableC2706uk(c2749vk, 0));
        }
        this.i.c();
        if (((Boolean) rVar.c.a(AbstractC2773w7.j9)).booleanValue()) {
            final int i = 0;
            AbstractC2270kd.a.execute(new Runnable(this) { // from class: com.google.android.gms.internal.ads.ff
                public final /* synthetic */ BinderC2144hf b;

                {
                    this.b = this;
                }

                @Override // java.lang.Runnable
                public final void run() throws com.google.android.gms.ads.internal.util.client.zzr {
                    boolean z;
                    String str;
                    String strB;
                    C2345m8 c2345m8;
                    switch (i) {
                        case 0:
                            BinderC2144hf binderC2144hf = this.b;
                            binderC2144hf.getClass();
                            com.google.android.gms.ads.internal.j jVar2 = com.google.android.gms.ads.internal.j.C;
                            com.google.android.gms.ads.internal.util.C cD3 = jVar2.h.d();
                            cD3.l();
                            synchronized (cD3.a) {
                                z = cD3.y;
                            }
                            if (z) {
                                com.google.android.gms.ads.internal.util.C cD4 = jVar2.h.d();
                                cD4.l();
                                synchronized (cD4.a) {
                                    str = cD4.z;
                                }
                                if (jVar2.o.f(binderC2144hf.a, str, binderC2144hf.b.a)) {
                                    return;
                                }
                                jVar2.h.d().r(false);
                                jVar2.h.d().q("");
                                return;
                            }
                            return;
                        case 1:
                            AbstractC1972di.o(this.b.a, true);
                            return;
                        case 2:
                            F7 f7 = com.google.android.gms.ads.internal.j.C.n;
                            BinderC2144hf binderC2144hf2 = this.b;
                            Context context2 = binderC2144hf2.a;
                            if (f7.b.getAndSet(true)) {
                                return;
                            }
                            f7.c = context2;
                            f7.d = binderC2144hf2.n;
                            if (f7.f != null || context2 == null || (strB = androidx.browser.customtabs.l.b(context2, null)) == null) {
                                return;
                            }
                            androidx.browser.customtabs.l.a(context2, strB, f7);
                            return;
                        default:
                            BinderC1762Rb binderC1762Rb = new BinderC1762Rb("com.google.android.gms.ads.internal.report.IDynamiteErrorEventListener");
                            C2302l8 c2302l8 = this.b.j;
                            c2302l8.getClass();
                            try {
                                try {
                                    IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(c2302l8.a).b("com.google.android.gms.ads.flags.FlagRetrieverSupplierProxy");
                                    if (iBinderB == null) {
                                        c2345m8 = null;
                                    } else {
                                        IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.ads.internal.flags.IFlagRetrieverSupplierProxy");
                                        c2345m8 = iInterfaceQueryLocalInterface instanceof C2345m8 ? (C2345m8) iInterfaceQueryLocalInterface : new C2345m8(iBinderB, "com.google.android.gms.ads.internal.flags.IFlagRetrieverSupplierProxy", 0);
                                    }
                                    Parcel parcelF3 = c2345m8.f3();
                                    AbstractC2857y5.e(parcelF3, binderC1762Rb);
                                    c2345m8.d4(1, parcelF3);
                                    return;
                                } catch (Exception e) {
                                    throw new com.google.android.gms.ads.internal.util.client.zzr(e);
                                }
                            } catch (RemoteException e2) {
                                com.google.android.gms.ads.internal.util.client.i.h("Error calling setFlagsAccessedBeforeInitializedListener: ".concat(String.valueOf(e2.getMessage())));
                                return;
                            } catch (com.google.android.gms.ads.internal.util.client.zzr e3) {
                                com.google.android.gms.ads.internal.util.client.i.h("Could not load com.google.android.gms.ads.flags.FlagRetrieverSupplierProxy:".concat(String.valueOf(e3.getMessage())));
                                return;
                            }
                    }
                }
            });
        }
        if (((Boolean) rVar.c.a(AbstractC2773w7.Va)).booleanValue()) {
            final int i2 = 3;
            AbstractC2270kd.a.execute(new Runnable(this) { // from class: com.google.android.gms.internal.ads.ff
                public final /* synthetic */ BinderC2144hf b;

                {
                    this.b = this;
                }

                @Override // java.lang.Runnable
                public final void run() throws com.google.android.gms.ads.internal.util.client.zzr {
                    boolean z;
                    String str;
                    String strB;
                    C2345m8 c2345m8;
                    switch (i2) {
                        case 0:
                            BinderC2144hf binderC2144hf = this.b;
                            binderC2144hf.getClass();
                            com.google.android.gms.ads.internal.j jVar2 = com.google.android.gms.ads.internal.j.C;
                            com.google.android.gms.ads.internal.util.C cD3 = jVar2.h.d();
                            cD3.l();
                            synchronized (cD3.a) {
                                z = cD3.y;
                            }
                            if (z) {
                                com.google.android.gms.ads.internal.util.C cD4 = jVar2.h.d();
                                cD4.l();
                                synchronized (cD4.a) {
                                    str = cD4.z;
                                }
                                if (jVar2.o.f(binderC2144hf.a, str, binderC2144hf.b.a)) {
                                    return;
                                }
                                jVar2.h.d().r(false);
                                jVar2.h.d().q("");
                                return;
                            }
                            return;
                        case 1:
                            AbstractC1972di.o(this.b.a, true);
                            return;
                        case 2:
                            F7 f7 = com.google.android.gms.ads.internal.j.C.n;
                            BinderC2144hf binderC2144hf2 = this.b;
                            Context context2 = binderC2144hf2.a;
                            if (f7.b.getAndSet(true)) {
                                return;
                            }
                            f7.c = context2;
                            f7.d = binderC2144hf2.n;
                            if (f7.f != null || context2 == null || (strB = androidx.browser.customtabs.l.b(context2, null)) == null) {
                                return;
                            }
                            androidx.browser.customtabs.l.a(context2, strB, f7);
                            return;
                        default:
                            BinderC1762Rb binderC1762Rb = new BinderC1762Rb("com.google.android.gms.ads.internal.report.IDynamiteErrorEventListener");
                            C2302l8 c2302l8 = this.b.j;
                            c2302l8.getClass();
                            try {
                                try {
                                    IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(c2302l8.a).b("com.google.android.gms.ads.flags.FlagRetrieverSupplierProxy");
                                    if (iBinderB == null) {
                                        c2345m8 = null;
                                    } else {
                                        IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.ads.internal.flags.IFlagRetrieverSupplierProxy");
                                        c2345m8 = iInterfaceQueryLocalInterface instanceof C2345m8 ? (C2345m8) iInterfaceQueryLocalInterface : new C2345m8(iBinderB, "com.google.android.gms.ads.internal.flags.IFlagRetrieverSupplierProxy", 0);
                                    }
                                    Parcel parcelF3 = c2345m8.f3();
                                    AbstractC2857y5.e(parcelF3, binderC1762Rb);
                                    c2345m8.d4(1, parcelF3);
                                    return;
                                } catch (Exception e) {
                                    throw new com.google.android.gms.ads.internal.util.client.zzr(e);
                                }
                            } catch (RemoteException e2) {
                                com.google.android.gms.ads.internal.util.client.i.h("Error calling setFlagsAccessedBeforeInitializedListener: ".concat(String.valueOf(e2.getMessage())));
                                return;
                            } catch (com.google.android.gms.ads.internal.util.client.zzr e3) {
                                com.google.android.gms.ads.internal.util.client.i.h("Could not load com.google.android.gms.ads.flags.FlagRetrieverSupplierProxy:".concat(String.valueOf(e3.getMessage())));
                                return;
                            }
                    }
                }
            });
        }
        if (((Boolean) rVar.c.a(AbstractC2773w7.c3)).booleanValue()) {
            final int i3 = 1;
            AbstractC2270kd.a.execute(new Runnable(this) { // from class: com.google.android.gms.internal.ads.ff
                public final /* synthetic */ BinderC2144hf b;

                {
                    this.b = this;
                }

                @Override // java.lang.Runnable
                public final void run() throws com.google.android.gms.ads.internal.util.client.zzr {
                    boolean z;
                    String str;
                    String strB;
                    C2345m8 c2345m8;
                    switch (i3) {
                        case 0:
                            BinderC2144hf binderC2144hf = this.b;
                            binderC2144hf.getClass();
                            com.google.android.gms.ads.internal.j jVar2 = com.google.android.gms.ads.internal.j.C;
                            com.google.android.gms.ads.internal.util.C cD3 = jVar2.h.d();
                            cD3.l();
                            synchronized (cD3.a) {
                                z = cD3.y;
                            }
                            if (z) {
                                com.google.android.gms.ads.internal.util.C cD4 = jVar2.h.d();
                                cD4.l();
                                synchronized (cD4.a) {
                                    str = cD4.z;
                                }
                                if (jVar2.o.f(binderC2144hf.a, str, binderC2144hf.b.a)) {
                                    return;
                                }
                                jVar2.h.d().r(false);
                                jVar2.h.d().q("");
                                return;
                            }
                            return;
                        case 1:
                            AbstractC1972di.o(this.b.a, true);
                            return;
                        case 2:
                            F7 f7 = com.google.android.gms.ads.internal.j.C.n;
                            BinderC2144hf binderC2144hf2 = this.b;
                            Context context2 = binderC2144hf2.a;
                            if (f7.b.getAndSet(true)) {
                                return;
                            }
                            f7.c = context2;
                            f7.d = binderC2144hf2.n;
                            if (f7.f != null || context2 == null || (strB = androidx.browser.customtabs.l.b(context2, null)) == null) {
                                return;
                            }
                            androidx.browser.customtabs.l.a(context2, strB, f7);
                            return;
                        default:
                            BinderC1762Rb binderC1762Rb = new BinderC1762Rb("com.google.android.gms.ads.internal.report.IDynamiteErrorEventListener");
                            C2302l8 c2302l8 = this.b.j;
                            c2302l8.getClass();
                            try {
                                try {
                                    IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(c2302l8.a).b("com.google.android.gms.ads.flags.FlagRetrieverSupplierProxy");
                                    if (iBinderB == null) {
                                        c2345m8 = null;
                                    } else {
                                        IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.ads.internal.flags.IFlagRetrieverSupplierProxy");
                                        c2345m8 = iInterfaceQueryLocalInterface instanceof C2345m8 ? (C2345m8) iInterfaceQueryLocalInterface : new C2345m8(iBinderB, "com.google.android.gms.ads.internal.flags.IFlagRetrieverSupplierProxy", 0);
                                    }
                                    Parcel parcelF3 = c2345m8.f3();
                                    AbstractC2857y5.e(parcelF3, binderC1762Rb);
                                    c2345m8.d4(1, parcelF3);
                                    return;
                                } catch (Exception e) {
                                    throw new com.google.android.gms.ads.internal.util.client.zzr(e);
                                }
                            } catch (RemoteException e2) {
                                com.google.android.gms.ads.internal.util.client.i.h("Error calling setFlagsAccessedBeforeInitializedListener: ".concat(String.valueOf(e2.getMessage())));
                                return;
                            } catch (com.google.android.gms.ads.internal.util.client.zzr e3) {
                                com.google.android.gms.ads.internal.util.client.i.h("Could not load com.google.android.gms.ads.flags.FlagRetrieverSupplierProxy:".concat(String.valueOf(e3.getMessage())));
                                return;
                            }
                    }
                }
            });
        }
        if (((Boolean) rVar.c.a(AbstractC2773w7.E4)).booleanValue()) {
            if (((Boolean) rVar.c.a(AbstractC2773w7.F4)).booleanValue()) {
                final int i4 = 2;
                AbstractC2270kd.a.execute(new Runnable(this) { // from class: com.google.android.gms.internal.ads.ff
                    public final /* synthetic */ BinderC2144hf b;

                    {
                        this.b = this;
                    }

                    @Override // java.lang.Runnable
                    public final void run() throws com.google.android.gms.ads.internal.util.client.zzr {
                        boolean z;
                        String str;
                        String strB;
                        C2345m8 c2345m8;
                        switch (i4) {
                            case 0:
                                BinderC2144hf binderC2144hf = this.b;
                                binderC2144hf.getClass();
                                com.google.android.gms.ads.internal.j jVar2 = com.google.android.gms.ads.internal.j.C;
                                com.google.android.gms.ads.internal.util.C cD3 = jVar2.h.d();
                                cD3.l();
                                synchronized (cD3.a) {
                                    z = cD3.y;
                                }
                                if (z) {
                                    com.google.android.gms.ads.internal.util.C cD4 = jVar2.h.d();
                                    cD4.l();
                                    synchronized (cD4.a) {
                                        str = cD4.z;
                                    }
                                    if (jVar2.o.f(binderC2144hf.a, str, binderC2144hf.b.a)) {
                                        return;
                                    }
                                    jVar2.h.d().r(false);
                                    jVar2.h.d().q("");
                                    return;
                                }
                                return;
                            case 1:
                                AbstractC1972di.o(this.b.a, true);
                                return;
                            case 2:
                                F7 f7 = com.google.android.gms.ads.internal.j.C.n;
                                BinderC2144hf binderC2144hf2 = this.b;
                                Context context2 = binderC2144hf2.a;
                                if (f7.b.getAndSet(true)) {
                                    return;
                                }
                                f7.c = context2;
                                f7.d = binderC2144hf2.n;
                                if (f7.f != null || context2 == null || (strB = androidx.browser.customtabs.l.b(context2, null)) == null) {
                                    return;
                                }
                                androidx.browser.customtabs.l.a(context2, strB, f7);
                                return;
                            default:
                                BinderC1762Rb binderC1762Rb = new BinderC1762Rb("com.google.android.gms.ads.internal.report.IDynamiteErrorEventListener");
                                C2302l8 c2302l8 = this.b.j;
                                c2302l8.getClass();
                                try {
                                    try {
                                        IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(c2302l8.a).b("com.google.android.gms.ads.flags.FlagRetrieverSupplierProxy");
                                        if (iBinderB == null) {
                                            c2345m8 = null;
                                        } else {
                                            IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.ads.internal.flags.IFlagRetrieverSupplierProxy");
                                            c2345m8 = iInterfaceQueryLocalInterface instanceof C2345m8 ? (C2345m8) iInterfaceQueryLocalInterface : new C2345m8(iBinderB, "com.google.android.gms.ads.internal.flags.IFlagRetrieverSupplierProxy", 0);
                                        }
                                        Parcel parcelF3 = c2345m8.f3();
                                        AbstractC2857y5.e(parcelF3, binderC1762Rb);
                                        c2345m8.d4(1, parcelF3);
                                        return;
                                    } catch (Exception e) {
                                        throw new com.google.android.gms.ads.internal.util.client.zzr(e);
                                    }
                                } catch (RemoteException e2) {
                                    com.google.android.gms.ads.internal.util.client.i.h("Error calling setFlagsAccessedBeforeInitializedListener: ".concat(String.valueOf(e2.getMessage())));
                                    return;
                                } catch (com.google.android.gms.ads.internal.util.client.zzr e3) {
                                    com.google.android.gms.ads.internal.util.client.i.h("Could not load com.google.android.gms.ads.flags.FlagRetrieverSupplierProxy:".concat(String.valueOf(e3.getMessage())));
                                    return;
                                }
                        }
                    }
                });
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void v0(InterfaceC1603k0 interfaceC1603k0) {
        this.i.d(interfaceC1603k0, EnumC2450ol.b);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void z2(com.google.android.gms.dynamic.a aVar, String str) {
        if (aVar == null) {
            com.google.android.gms.ads.internal.util.client.i.e("Wrapped context is null. Failed to open debug menu.");
            return;
        }
        Context context = (Context) com.google.android.gms.dynamic.b.I3(aVar);
        if (context == null) {
            com.google.android.gms.ads.internal.util.client.i.e("Context is null. Failed to open debug menu.");
            return;
        }
        C1633i c1633i = new C1633i(context);
        c1633i.d = str;
        c1633i.e = this.b.a;
        c1633i.b();
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final synchronized float zze() {
        return com.google.android.gms.ads.internal.j.C.i.a();
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1585b0
    public final void zzi() {
        this.f.q = false;
    }
}
