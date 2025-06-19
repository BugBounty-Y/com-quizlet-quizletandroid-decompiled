package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.Parcel;
import java.util.List;

/* loaded from: classes2.dex */
public final class Rj extends AbstractBinderC2814x5 implements G8 {
    public final String a;
    public final Ui b;
    public final Yi c;

    public Rj(String str, Ui ui, Yi yi) {
        super("com.google.android.gms.ads.internal.formats.client.INativeAppInstallAd");
        this.a = str;
        this.b = ui;
        this.c = yi;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        List list;
        InterfaceC2860y8 interfaceC2860y8;
        double d;
        String strC;
        String strC2;
        com.google.android.gms.dynamic.a aVar;
        Ui ui = this.b;
        Yi yi = this.c;
        switch (i) {
            case 2:
                com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(ui);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, bVar);
                return true;
            case 3:
                String strB = yi.b();
                parcel2.writeNoException();
                parcel2.writeString(strB);
                return true;
            case 4:
                synchronized (yi) {
                    list = yi.e;
                }
                parcel2.writeNoException();
                parcel2.writeList(list);
                return true;
            case 5:
                String strQ = yi.q();
                parcel2.writeNoException();
                parcel2.writeString(strQ);
                return true;
            case 6:
                synchronized (yi) {
                    interfaceC2860y8 = yi.s;
                }
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2860y8);
                return true;
            case 7:
                String strR = yi.r();
                parcel2.writeNoException();
                parcel2.writeString(strR);
                return true;
            case 8:
                synchronized (yi) {
                    d = yi.r;
                }
                parcel2.writeNoException();
                parcel2.writeDouble(d);
                return true;
            case 9:
                synchronized (yi) {
                    strC = yi.c("store");
                }
                parcel2.writeNoException();
                parcel2.writeString(strC);
                return true;
            case 10:
                synchronized (yi) {
                    strC2 = yi.c("price");
                }
                parcel2.writeNoException();
                parcel2.writeString(strC2);
                return true;
            case 11:
                Bundle bundleH = yi.h();
                parcel2.writeNoException();
                AbstractC2857y5.d(parcel2, bundleH);
                return true;
            case 12:
                ui.r();
                parcel2.writeNoException();
                return true;
            case 13:
                com.google.android.gms.ads.internal.client.v0 v0VarI = yi.i();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, v0VarI);
                return true;
            case 14:
                Bundle bundle = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                AbstractC2857y5.b(parcel);
                synchronized (ui) {
                    ui.l.g(bundle);
                }
                parcel2.writeNoException();
                return true;
            case 15:
                Bundle bundle2 = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                AbstractC2857y5.b(parcel);
                boolean zI = ui.i(bundle2);
                parcel2.writeNoException();
                parcel2.writeInt(zI ? 1 : 0);
                return true;
            case 16:
                Bundle bundle3 = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                AbstractC2857y5.b(parcel);
                synchronized (ui) {
                    ui.l.d(bundle3);
                }
                parcel2.writeNoException();
                return true;
            case 17:
                InterfaceC2645t8 interfaceC2645t8J = yi.j();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2645t8J);
                return true;
            case 18:
                synchronized (yi) {
                    aVar = yi.q;
                }
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, aVar);
                return true;
            case 19:
                parcel2.writeNoException();
                parcel2.writeString(this.a);
                return true;
            default:
                return false;
        }
    }
}
