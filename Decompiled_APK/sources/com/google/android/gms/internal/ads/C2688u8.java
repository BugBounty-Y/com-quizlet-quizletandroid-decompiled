package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.u8, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2688u8 {
    public final ArrayList a;

    public C2688u8(InterfaceC2645t8 interfaceC2645t8, int i) {
        IBinder iBinder;
        switch (i) {
            case 1:
                this.a = new ArrayList();
                try {
                    interfaceC2645t8.h();
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e);
                }
                try {
                    for (Object obj : interfaceC2645t8.g()) {
                        InterfaceC2860y8 interfaceC2860y8E4 = obj instanceof IBinder ? BinderC2474p8.e4((IBinder) obj) : null;
                        if (interfaceC2860y8E4 != null) {
                            this.a.add(new C2568rb(interfaceC2860y8E4));
                        }
                    }
                    break;
                } catch (RemoteException e2) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e2);
                    return;
                }
            default:
                this.a = new ArrayList();
                try {
                    interfaceC2645t8.h();
                } catch (RemoteException e3) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e3);
                }
                try {
                    for (Object obj2 : interfaceC2645t8.g()) {
                        InterfaceC2860y8 c2817x8 = null;
                        if ((obj2 instanceof IBinder) && (iBinder = (IBinder) obj2) != null) {
                            IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.INativeAdImage");
                            c2817x8 = iInterfaceQueryLocalInterface instanceof InterfaceC2860y8 ? (InterfaceC2860y8) iInterfaceQueryLocalInterface : new C2817x8(iBinder);
                        }
                        if (c2817x8 != null) {
                            this.a.add(new C2903z8(c2817x8));
                        }
                    }
                    break;
                } catch (RemoteException e4) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e4);
                }
                break;
        }
    }
}
