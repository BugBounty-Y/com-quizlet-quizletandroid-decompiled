package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.C1633i;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;

/* loaded from: classes2.dex */
public final /* synthetic */ class Jg implements InterfaceC2544qt {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ Jg(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                Vp vp = (Vp) obj;
                C1633i c1633i = new C1633i((Context) this.b);
                c1633i.c = vp.B;
                c1633i.f = vp.C.toString();
                c1633i.e = ((VersionInfoParcel) this.c).a;
                c1633i.d = ((C2023eq) this.d).f;
                return c1633i;
            case 1:
                Vp vp2 = (Vp) this.c;
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.b;
                if (vp2.M) {
                    interfaceC2529qe.U();
                }
                interfaceC2529qe.P0();
                interfaceC2529qe.onPause();
                return ((C1771Se) this.d).O();
            case 2:
                Vp vp3 = (Vp) this.c;
                InterfaceC2529qe interfaceC2529qe2 = (InterfaceC2529qe) this.b;
                if (vp3.M) {
                    interfaceC2529qe2.U();
                }
                interfaceC2529qe2.P0();
                interfaceC2529qe2.onPause();
                return ((C1807Ye) this.d).O();
            default:
                Vp vp4 = (Vp) this.c;
                InterfaceC2529qe interfaceC2529qe3 = (InterfaceC2529qe) this.b;
                if (vp4.M) {
                    interfaceC2529qe3.U();
                }
                interfaceC2529qe3.P0();
                interfaceC2529qe3.onPause();
                return ((C1838af) this.d).O();
        }
    }
}
