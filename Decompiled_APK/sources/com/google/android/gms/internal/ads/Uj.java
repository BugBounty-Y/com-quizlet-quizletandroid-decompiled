package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Parcel;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import androidx.collection.C0208f;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class Uj extends AbstractBinderC2814x5 implements J8 {
    public final Context a;
    public final Yi b;
    public C2191ij c;
    public Ui d;

    public Uj(Context context, Yi yi, C2191ij c2191ij, Ui ui) {
        super("com.google.android.gms.ads.internal.formats.client.INativeCustomTemplateAd");
        this.a = context;
        this.b = yi;
        this.c = c2191ij;
        this.d = ui;
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final void T(String str) {
        Ui ui = this.d;
        if (ui != null) {
            synchronized (ui) {
                ui.l.T(str);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final boolean U(com.google.android.gms.dynamic.a aVar) throws SecurityException {
        C2191ij c2191ij;
        Object objI3 = com.google.android.gms.dynamic.b.I3(aVar);
        if (!(objI3 instanceof ViewGroup) || (c2191ij = this.c) == null || !c2191ij.c((ViewGroup) objI3, true)) {
            return false;
        }
        this.b.m().L0(new Ts(this, 21));
        return true;
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final boolean W(com.google.android.gms.dynamic.a aVar) throws SecurityException {
        C2191ij c2191ij;
        InterfaceC2529qe interfaceC2529qe;
        Object objI3 = com.google.android.gms.dynamic.b.I3(aVar);
        if (!(objI3 instanceof ViewGroup) || (c2191ij = this.c) == null || !c2191ij.c((ViewGroup) objI3, false)) {
            return false;
        }
        Yi yi = this.b;
        synchronized (yi) {
            interfaceC2529qe = yi.j;
        }
        interfaceC2529qe.L0(new Ts(this, 21));
        return true;
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final InterfaceC2860y8 Z(String str) {
        androidx.collection.V v;
        Yi yi = this.b;
        synchronized (yi) {
            v = yi.v;
        }
        return (InterfaceC2860y8) v.get(str);
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) throws SecurityException {
        Ui ui;
        int i2 = 0;
        Yi yi = this.b;
        switch (i) {
            case 1:
                String string = parcel.readString();
                AbstractC2857y5.b(parcel);
                String strR3 = r3(string);
                parcel2.writeNoException();
                parcel2.writeString(strR3);
                return true;
            case 2:
                String string2 = parcel.readString();
                AbstractC2857y5.b(parcel);
                InterfaceC2860y8 interfaceC2860y8Z = Z(string2);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2860y8Z);
                return true;
            case 3:
                List<String> listN = n();
                parcel2.writeNoException();
                parcel2.writeStringList(listN);
                return true;
            case 4:
                String strA = yi.a();
                parcel2.writeNoException();
                parcel2.writeString(strA);
                return true;
            case 5:
                String string3 = parcel.readString();
                AbstractC2857y5.b(parcel);
                T(string3);
                parcel2.writeNoException();
                return true;
            case 6:
                v();
                parcel2.writeNoException();
                return true;
            case 7:
                com.google.android.gms.ads.internal.client.v0 v0VarI = yi.i();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, v0VarI);
                return true;
            case 8:
                k();
                parcel2.writeNoException();
                return true;
            case 9:
                com.google.android.gms.dynamic.a aVarG = g();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, aVarG);
                return true;
            case 10:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                boolean zU = U(aVarV3);
                parcel2.writeNoException();
                parcel2.writeInt(zU ? 1 : 0);
                return true;
            case 11:
                parcel2.writeNoException();
                ClassLoader classLoader = AbstractC2857y5.a;
                parcel2.writeStrongBinder(null);
                return true;
            case 12:
                boolean zP = p();
                parcel2.writeNoException();
                ClassLoader classLoader2 = AbstractC2857y5.a;
                parcel2.writeInt(zP ? 1 : 0);
                return true;
            case 13:
                C2665tm c2665tmO = yi.o();
                if (c2665tmO != null) {
                    C2147hi c2147hi = com.google.android.gms.ads.internal.j.C.x;
                    Hr hr = c2665tmO.a;
                    c2147hi.getClass();
                    C2147hi.k(hr);
                    if (yi.l() != null) {
                        yi.l().j("onSdkLoaded", new C0208f(0));
                    }
                    i2 = 1;
                } else {
                    com.google.android.gms.ads.internal.util.client.i.h("Trying to start OMID session before creation.");
                }
                parcel2.writeNoException();
                ClassLoader classLoader3 = AbstractC2857y5.a;
                parcel2.writeInt(i2);
                return true;
            case 14:
                com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                Object objI3 = com.google.android.gms.dynamic.b.I3(aVarV32);
                if ((objI3 instanceof View) && yi.o() != null && (ui = this.d) != null) {
                    ui.e((View) objI3);
                }
                parcel2.writeNoException();
                return true;
            case 15:
                l();
                parcel2.writeNoException();
                return true;
            case 16:
                InterfaceC2774w8 interfaceC2774w8F = f();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2774w8F);
                return true;
            case 17:
                com.google.android.gms.dynamic.a aVarV33 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                boolean zW = W(aVarV33);
                parcel2.writeNoException();
                parcel2.writeInt(zW ? 1 : 0);
                return true;
            default:
                return false;
        }
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final InterfaceC2774w8 f() {
        InterfaceC2774w8 interfaceC2774w8;
        try {
            Wi wi = this.d.D;
            synchronized (wi) {
                interfaceC2774w8 = wi.a;
            }
            return interfaceC2774w8;
        } catch (NullPointerException e) {
            com.google.android.gms.ads.internal.j.C.h.h("InternalNativeCustomTemplateAdShim.getMediaContent", e);
            return null;
        }
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final com.google.android.gms.dynamic.a g() {
        return new com.google.android.gms.dynamic.b(this.a);
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final void k() {
        Ui ui = this.d;
        if (ui != null) {
            ui.r();
        }
        this.d = null;
        this.c = null;
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final void l() {
        String str;
        try {
            Yi yi = this.b;
            synchronized (yi) {
                str = yi.y;
            }
            if (Objects.equals(str, "Google")) {
                com.google.android.gms.ads.internal.util.client.i.h("Illegal argument specified for omid partner name.");
                return;
            }
            if (TextUtils.isEmpty(str)) {
                com.google.android.gms.ads.internal.util.client.i.h("Not starting OMID session. OM partner name has not been configured.");
                return;
            }
            Ui ui = this.d;
            if (ui != null) {
                ui.s(str, false);
            }
        } catch (NullPointerException e) {
            com.google.android.gms.ads.internal.j.C.h.h("InternalNativeCustomTemplateAdShim.initializeDisplayOpenMeasurement", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final List n() {
        androidx.collection.V v;
        androidx.collection.V v2;
        try {
            Yi yi = this.b;
            synchronized (yi) {
                v = yi.v;
            }
            synchronized (yi) {
                v2 = yi.w;
            }
            String[] strArr = new String[v.c + v2.c];
            int i = 0;
            for (int i2 = 0; i2 < v.c; i2++) {
                strArr[i] = (String) v.g(i2);
                i++;
            }
            for (int i3 = 0; i3 < v2.c; i3++) {
                strArr[i] = (String) v2.g(i3);
                i++;
            }
            return Arrays.asList(strArr);
        } catch (NullPointerException e) {
            com.google.android.gms.ads.internal.j.C.h.h("InternalNativeCustomTemplateAdShim.getAvailableAssetNames", e);
            return new ArrayList();
        }
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final boolean p() {
        Ui ui = this.d;
        if (ui != null && !ui.n.c()) {
            return false;
        }
        Yi yi = this.b;
        return yi.l() != null && yi.m() == null;
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final String r3(String str) {
        androidx.collection.V v;
        Yi yi = this.b;
        synchronized (yi) {
            v = yi.w;
        }
        return (String) v.get(str);
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final void v() {
        Ui ui = this.d;
        if (ui != null) {
            synchronized (ui) {
                if (ui.w) {
                    return;
                }
                ui.l.c();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final String zzi() {
        return this.b.a();
    }
}
