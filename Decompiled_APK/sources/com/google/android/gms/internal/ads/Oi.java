package com.google.android.gms.internal.ads;

import android.graphics.drawable.Drawable;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class Oi extends AbstractBinderC2814x5 implements InterfaceC2774w8 {
    public final Yi a;
    public com.google.android.gms.dynamic.a b;

    public Oi(Yi yi) {
        super("com.google.android.gms.ads.internal.formats.client.IMediaContent");
        this.a = yi;
    }

    public static float e4(com.google.android.gms.dynamic.a aVar) {
        Drawable drawable;
        return (aVar == null || (drawable = (Drawable) com.google.android.gms.dynamic.b.I3(aVar)) == null || drawable.getIntrinsicWidth() == -1 || drawable.getIntrinsicHeight() == -1) ? DefinitionKt.NO_Float_VALUE : drawable.getIntrinsicWidth() / drawable.getIntrinsicHeight();
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        float f;
        Q8 q8;
        float fZze = DefinitionKt.NO_Float_VALUE;
        switch (i) {
            case 2:
                Yi yi = this.a;
                synchronized (yi) {
                    f = yi.x;
                }
                if (f != DefinitionKt.NO_Float_VALUE) {
                    synchronized (yi) {
                        fZze = yi.x;
                    }
                } else if (yi.i() != null) {
                    try {
                        fZze = yi.i().zze();
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.i.f("Remote exception getting video controller aspect ratio.", e);
                    }
                } else {
                    com.google.android.gms.dynamic.a aVar = this.b;
                    if (aVar != null) {
                        fZze = e4(aVar);
                    } else {
                        InterfaceC2860y8 interfaceC2860y8K = yi.k();
                        if (interfaceC2860y8K != null) {
                            float fJ = (interfaceC2860y8K.j() == -1 || interfaceC2860y8K.a() == -1) ? 0.0f : interfaceC2860y8K.j() / interfaceC2860y8K.a();
                            fZze = fJ == DefinitionKt.NO_Float_VALUE ? e4(interfaceC2860y8K.f()) : fJ;
                        }
                    }
                }
                parcel2.writeNoException();
                parcel2.writeFloat(fZze);
                return true;
            case 3:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                this.b = aVarV3;
                parcel2.writeNoException();
                return true;
            case 4:
                com.google.android.gms.dynamic.a aVarZzi = zzi();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, aVarZzi);
                return true;
            case 5:
                Yi yi2 = this.a;
                if (yi2.i() != null) {
                    fZze = yi2.i().h();
                }
                parcel2.writeNoException();
                parcel2.writeFloat(fZze);
                return true;
            case 6:
                Yi yi3 = this.a;
                if (yi3.i() != null) {
                    fZze = yi3.i().f();
                }
                parcel2.writeNoException();
                parcel2.writeFloat(fZze);
                return true;
            case 7:
                com.google.android.gms.ads.internal.client.v0 v0VarI = this.a.i();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, v0VarI);
                return true;
            case 8:
                boolean zK = k();
                parcel2.writeNoException();
                ClassLoader classLoader = AbstractC2857y5.a;
                parcel2.writeInt(zK ? 1 : 0);
                return true;
            case 9:
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder == null) {
                    q8 = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.IOnMediaContentChangedListener");
                    q8 = iInterfaceQueryLocalInterface instanceof Q8 ? (Q8) iInterfaceQueryLocalInterface : new Q8(strongBinder, "com.google.android.gms.ads.internal.formats.client.IOnMediaContentChangedListener", 0);
                }
                AbstractC2857y5.b(parcel);
                Yi yi4 = this.a;
                if (yi4.i() instanceof BinderC2915ze) {
                    BinderC2915ze binderC2915ze = (BinderC2915ze) yi4.i();
                    synchronized (binderC2915ze.b) {
                        binderC2915ze.n = q8;
                    }
                }
                parcel2.writeNoException();
                return true;
            case 10:
                boolean zT = t();
                parcel2.writeNoException();
                ClassLoader classLoader2 = AbstractC2857y5.a;
                parcel2.writeInt(zT ? 1 : 0);
                return true;
            default:
                return false;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2774w8
    public final com.google.android.gms.ads.internal.client.v0 g() {
        return this.a.i();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2774w8
    public final boolean k() {
        return this.a.i() != null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2774w8
    public final boolean t() {
        InterfaceC2529qe interfaceC2529qe;
        Yi yi = this.a;
        synchronized (yi) {
            interfaceC2529qe = yi.j;
        }
        return interfaceC2529qe != null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2774w8
    public final com.google.android.gms.dynamic.a zzi() {
        com.google.android.gms.dynamic.a aVar = this.b;
        if (aVar != null) {
            return aVar;
        }
        InterfaceC2860y8 interfaceC2860y8K = this.a.k();
        if (interfaceC2860y8K == null) {
            return null;
        }
        return interfaceC2860y8K.f();
    }
}
