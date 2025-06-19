package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.Parcel;
import java.util.List;

/* loaded from: classes2.dex */
public final class Tj extends AbstractBinderC2814x5 implements H8 {
    public final String a;
    public final Ui b;
    public final Yi c;

    public Tj(String str, Ui ui, Yi yi) {
        super("com.google.android.gms.ads.internal.formats.client.INativeContentAd");
        this.a = str;
        this.b = ui;
        this.c = yi;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        List list;
        InterfaceC2860y8 interfaceC2860y8;
        com.google.android.gms.dynamic.a aVar;
        switch (i) {
            case 2:
                com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(this.b);
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, bVar);
                return true;
            case 3:
                String strB = this.c.b();
                parcel2.writeNoException();
                parcel2.writeString(strB);
                return true;
            case 4:
                Yi yi = this.c;
                synchronized (yi) {
                    list = yi.e;
                }
                parcel2.writeNoException();
                parcel2.writeList(list);
                return true;
            case 5:
                String strQ = this.c.q();
                parcel2.writeNoException();
                parcel2.writeString(strQ);
                return true;
            case 6:
                Yi yi2 = this.c;
                synchronized (yi2) {
                    interfaceC2860y8 = yi2.t;
                }
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2860y8);
                return true;
            case 7:
                String strR = this.c.r();
                parcel2.writeNoException();
                parcel2.writeString(strR);
                return true;
            case 8:
                String strP = this.c.p();
                parcel2.writeNoException();
                parcel2.writeString(strP);
                return true;
            case 9:
                Bundle bundleH = this.c.h();
                parcel2.writeNoException();
                AbstractC2857y5.d(parcel2, bundleH);
                return true;
            case 10:
                this.b.r();
                parcel2.writeNoException();
                return true;
            case 11:
                com.google.android.gms.ads.internal.client.v0 v0VarI = this.c.i();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, v0VarI);
                return true;
            case 12:
                Bundle bundle = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                AbstractC2857y5.b(parcel);
                Ui ui = this.b;
                synchronized (ui) {
                    ui.l.g(bundle);
                }
                parcel2.writeNoException();
                return true;
            case 13:
                Bundle bundle2 = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                AbstractC2857y5.b(parcel);
                boolean zI = this.b.i(bundle2);
                parcel2.writeNoException();
                parcel2.writeInt(zI ? 1 : 0);
                return true;
            case 14:
                Bundle bundle3 = (Bundle) AbstractC2857y5.a(parcel, Bundle.CREATOR);
                AbstractC2857y5.b(parcel);
                Ui ui2 = this.b;
                synchronized (ui2) {
                    ui2.l.d(bundle3);
                }
                parcel2.writeNoException();
                return true;
            case 15:
                InterfaceC2645t8 interfaceC2645t8J = this.c.j();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC2645t8J);
                return true;
            case 16:
                Yi yi3 = this.c;
                synchronized (yi3) {
                    aVar = yi3.q;
                }
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, aVar);
                return true;
            case 17:
                String str = this.a;
                parcel2.writeNoException();
                parcel2.writeString(str);
                return true;
            default:
                return false;
        }
    }
}
