package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.C1591e0;
import com.google.android.gms.ads.internal.client.InterfaceC1595g0;
import com.google.android.gms.ads.internal.client.InterfaceC1609n0;
import java.util.Collections;
import java.util.List;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Vj extends AbstractBinderC2814x5 implements Y8 {
    public final String a;
    public final Ui b;
    public final Yi c;
    public final Hk d;

    public Vj(String str, Ui ui, Yi yi, Hk hk) {
        super("com.google.android.gms.ads.internal.formats.client.IUnifiedNativeAd");
        this.a = str;
        this.b = ui;
        this.c = yi;
        this.d = hk;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final void I1(Bundle bundle) throws JSONException {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Tc)).booleanValue()) {
            Ui ui = this.b;
            InterfaceC2529qe interfaceC2529qeM = ui.k.m();
            if (interfaceC2529qeM == null) {
                com.google.android.gms.ads.internal.util.client.i.e("Video webview is null");
                return;
            }
            try {
                JSONObject jSONObject = new JSONObject();
                for (String str : bundle.keySet()) {
                    jSONObject.put(str, bundle.get(str));
                }
                ui.j.execute(new RunnableC1712If(interfaceC2529qeM, jSONObject));
            } catch (JSONException e) {
                com.google.android.gms.ads.internal.util.client.i.f("Error reading event signals", e);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final List c() {
        List list;
        Yi yi = this.c;
        synchronized (yi) {
            list = yi.e;
        }
        return list;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final List d() {
        List list;
        com.google.android.gms.ads.internal.client.E0 e0;
        List list2;
        Yi yi = this.c;
        synchronized (yi) {
            list = yi.f;
        }
        if (!list.isEmpty()) {
            synchronized (yi) {
                e0 = yi.g;
            }
            if (e0 != null) {
                Yi yi2 = this.c;
                synchronized (yi2) {
                    list2 = yi2.f;
                }
                return list2;
            }
        }
        return Collections.EMPTY_LIST;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) throws JSONException {
        List list;
        InterfaceC2860y8 interfaceC2860y8;
        double d;
        String strC;
        String strC2;
        com.google.android.gms.dynamic.a aVar;
        List list2;
        com.google.android.gms.ads.internal.client.E0 e0;
        InterfaceC2774w8 interfaceC2774w8;
        boolean zJ;
        int i2 = 0;
        V8 v8 = null;
        C1591e0 c1591e0 = null;
        switch (i) {
            case 2:
                String strB = this.c.b();
                parcel2.writeNoException();
                parcel2.writeString(strB);
                return true;
            case 3:
                Yi yi = this.c;
                synchronized (yi) {
                    list = yi.e;
                }
                parcel2.writeNoException();
                parcel2.writeList(list);
                return true;
            case 4:
                String strQ = this.c.q();
                parcel2.writeNoException();
                parcel2.writeString(strQ);
                return true;
            case 5:
                Yi yi2 = this.c;
                synchronized (yi2) {
                    interfaceC2860y8 = yi2.s;
                }
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2860y8);
                return true;
            case 6:
                String strR = this.c.r();
                parcel2.writeNoException();
                parcel2.writeString(strR);
                return true;
            case 7:
                String strP = this.c.p();
                parcel2.writeNoException();
                parcel2.writeString(strP);
                return true;
            case 8:
                Yi yi3 = this.c;
                synchronized (yi3) {
                    d = yi3.r;
                }
                parcel2.writeNoException();
                parcel2.writeDouble(d);
                return true;
            case 9:
                Yi yi4 = this.c;
                synchronized (yi4) {
                    strC = yi4.c("store");
                }
                parcel2.writeNoException();
                parcel2.writeString(strC);
                return true;
            case 10:
                Yi yi5 = this.c;
                synchronized (yi5) {
                    strC2 = yi5.c("price");
                }
                parcel2.writeNoException();
                parcel2.writeString(strC2);
                return true;
            case 11:
                com.google.android.gms.ads.internal.client.v0 v0VarI = this.c.i();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, v0VarI);
                return true;
            case 12:
                String str = this.a;
                parcel2.writeNoException();
                parcel2.writeString(str);
                return true;
            case 13:
                this.b.r();
                parcel2.writeNoException();
                return true;
            case 14:
                InterfaceC2645t8 interfaceC2645t8J = this.c.j();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2645t8J);
                return true;
            case 15:
                Bundle bundle = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                AbstractC2857y5.b(parcel);
                Ui ui = this.b;
                synchronized (ui) {
                    ui.l.g(bundle);
                }
                parcel2.writeNoException();
                return true;
            case 16:
                Bundle bundle2 = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                AbstractC2857y5.b(parcel);
                boolean zI = this.b.i(bundle2);
                parcel2.writeNoException();
                parcel2.writeInt(zI ? 1 : 0);
                return true;
            case 17:
                Bundle bundle3 = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                AbstractC2857y5.b(parcel);
                Ui ui2 = this.b;
                synchronized (ui2) {
                    ui2.l.d(bundle3);
                }
                parcel2.writeNoException();
                return true;
            case 18:
                com.google.android.gms.dynamic.a aVarL = l();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, aVarL);
                return true;
            case 19:
                Yi yi6 = this.c;
                synchronized (yi6) {
                    aVar = yi6.q;
                }
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, aVar);
                return true;
            case 20:
                Bundle bundleH = this.c.h();
                parcel2.writeNoException();
                AbstractC2857y5.d(parcel2, bundleH);
                return true;
            case 21:
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.IUnconfirmedClickListener");
                    v8 = iInterfaceQueryLocalInterface instanceof V8 ? (V8) iInterfaceQueryLocalInterface : new V8(strongBinder, "com.google.android.gms.ads.internal.formats.client.IUnconfirmedClickListener", 0);
                }
                AbstractC2857y5.b(parcel);
                f4(v8);
                parcel2.writeNoException();
                return true;
            case EventType.WINDOW_STATE /* 22 */:
                Ui ui3 = this.b;
                synchronized (ui3) {
                    ui3.l.i();
                }
                parcel2.writeNoException();
                return true;
            case EventType.AUDIO /* 23 */:
                List listD = d();
                parcel2.writeNoException();
                parcel2.writeList(listD);
                return true;
            case EventType.VIDEO /* 24 */:
                Yi yi7 = this.c;
                synchronized (yi7) {
                    list2 = yi7.f;
                }
                if (!list2.isEmpty()) {
                    synchronized (yi7) {
                        e0 = yi7.g;
                    }
                    if (e0 != null) {
                        i2 = 1;
                    }
                }
                parcel2.writeNoException();
                ClassLoader classLoader = AbstractC2857y5.a;
                parcel2.writeInt(i2);
                return true;
            case EventType.SUBS /* 25 */:
                InterfaceC1595g0 interfaceC1595g0E4 = com.google.android.gms.ads.internal.client.E0.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                g4(interfaceC1595g0E4);
                parcel2.writeNoException();
                return true;
            case EventType.CDN /* 26 */:
                IBinder strongBinder2 = parcel.readStrongBinder();
                if (strongBinder2 != null) {
                    IInterface iInterfaceQueryLocalInterface2 = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.client.IMuteThisAdListener");
                    c1591e0 = iInterfaceQueryLocalInterface2 instanceof C1591e0 ? (C1591e0) iInterfaceQueryLocalInterface2 : new C1591e0(strongBinder2, "com.google.android.gms.ads.internal.client.IMuteThisAdListener", 0);
                }
                AbstractC2857y5.b(parcel);
                e4(c1591e0);
                parcel2.writeNoException();
                return true;
            case 27:
                Ui ui4 = this.b;
                synchronized (ui4) {
                    ui4.l.B();
                }
                parcel2.writeNoException();
                return true;
            case 28:
                Ui ui5 = this.b;
                synchronized (ui5) {
                    AbstractBinderC2814x5 abstractBinderC2814x5 = ui5.u;
                    if (abstractBinderC2814x5 == null) {
                        com.google.android.gms.ads.internal.util.client.i.d("Ad should be associated with an ad view before calling recordCustomClickGesture()");
                    } else {
                        ui5.j.execute(new com.bumptech.glide.manager.o(abstractBinderC2814x5 instanceof ViewTreeObserverOnGlobalLayoutListenerC2060fj, 5, ui5));
                    }
                }
                parcel2.writeNoException();
                return true;
            case 29:
                Wi wi = this.b.D;
                synchronized (wi) {
                    interfaceC2774w8 = wi.a;
                }
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2774w8);
                return true;
            case 30:
                Ui ui6 = this.b;
                synchronized (ui6) {
                    zJ = ui6.l.J();
                }
                parcel2.writeNoException();
                ClassLoader classLoader2 = AbstractC2857y5.a;
                parcel2.writeInt(zJ ? 1 : 0);
                return true;
            case 31:
                com.google.android.gms.ads.internal.client.s0 s0VarH = h();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, s0VarH);
                return true;
            case 32:
                InterfaceC1609n0 interfaceC1609n0E4 = com.google.android.gms.ads.internal.client.N0.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                try {
                    if (!interfaceC1609n0E4.f()) {
                        this.d.b();
                    }
                } catch (RemoteException unused) {
                    com.google.android.gms.ads.internal.util.client.i.k(3);
                }
                Ui ui7 = this.b;
                synchronized (ui7) {
                    ui7.E.a.set(interfaceC1609n0E4);
                }
                parcel2.writeNoException();
                return true;
            case 33:
                Bundle bundle4 = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                AbstractC2857y5.b(parcel);
                I1(bundle4);
                parcel2.writeNoException();
                return true;
            default:
                return false;
        }
    }

    public final void e4(C1591e0 c1591e0) {
        Ui ui = this.b;
        synchronized (ui) {
            ui.l.t(c1591e0);
        }
    }

    public final void f4(V8 v8) {
        Ui ui = this.b;
        synchronized (ui) {
            ui.l.l(v8);
        }
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final com.google.android.gms.ads.internal.client.v0 g() {
        return this.c.i();
    }

    public final void g4(InterfaceC1595g0 interfaceC1595g0) {
        Ui ui = this.b;
        synchronized (ui) {
            ui.l.q(interfaceC1595g0);
        }
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final com.google.android.gms.ads.internal.client.s0 h() {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.H6)).booleanValue()) {
            return this.b.f;
        }
        return null;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final com.google.android.gms.dynamic.a k() {
        com.google.android.gms.dynamic.a aVar;
        Yi yi = this.c;
        synchronized (yi) {
            aVar = yi.q;
        }
        return aVar;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final com.google.android.gms.dynamic.a l() {
        return new com.google.android.gms.dynamic.b(this.b);
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final String m() {
        return this.c.p();
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final InterfaceC2860y8 n() {
        InterfaceC2860y8 interfaceC2860y8;
        Yi yi = this.c;
        synchronized (yi) {
            interfaceC2860y8 = yi.s;
        }
        return interfaceC2860y8;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final String o() {
        return this.c.r();
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final String p() {
        return this.c.b();
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final String s() {
        String strC;
        Yi yi = this.c;
        synchronized (yi) {
            strC = yi.c("store");
        }
        return strC;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final String x() {
        return this.c.q();
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final String z() {
        String strC;
        Yi yi = this.c;
        synchronized (yi) {
            strC = yi.c("price");
        }
        return strC;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final double zze() {
        double d;
        Yi yi = this.c;
        synchronized (yi) {
            d = yi.r;
        }
        return d;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final InterfaceC2645t8 zzi() {
        return this.c.j();
    }
}
