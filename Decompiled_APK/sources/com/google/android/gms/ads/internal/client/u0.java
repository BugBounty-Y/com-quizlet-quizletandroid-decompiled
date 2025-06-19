package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC2857y5;

/* loaded from: classes2.dex */
public abstract class u0 extends AbstractBinderC2814x5 implements v0 {
    public u0() {
        super("com.google.android.gms.ads.internal.client.IVideoController");
    }

    public static v0 e4(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IVideoController");
        return iInterfaceQueryLocalInterface instanceof v0 ? (v0) iInterfaceQueryLocalInterface : new t0(iBinder);
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        w0 w0Var;
        switch (i) {
            case 1:
                k();
                parcel2.writeNoException();
                return true;
            case 2:
                t();
                parcel2.writeNoException();
                return true;
            case 3:
                boolean zF = AbstractC2857y5.f(parcel);
                AbstractC2857y5.b(parcel);
                E(zF);
                parcel2.writeNoException();
                return true;
            case 4:
                boolean zP = p();
                parcel2.writeNoException();
                ClassLoader classLoader = AbstractC2857y5.a;
                parcel2.writeInt(zP ? 1 : 0);
                return true;
            case 5:
                int iG = g();
                parcel2.writeNoException();
                parcel2.writeInt(iG);
                return true;
            case 6:
                float fH = h();
                parcel2.writeNoException();
                parcel2.writeFloat(fH);
                return true;
            case 7:
                float f = f();
                parcel2.writeNoException();
                parcel2.writeFloat(f);
                return true;
            case 8:
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder == null) {
                    w0Var = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IVideoLifecycleCallbacks");
                    w0Var = iInterfaceQueryLocalInterface instanceof w0 ? (w0) iInterfaceQueryLocalInterface : new w0(strongBinder);
                }
                AbstractC2857y5.b(parcel);
                e2(w0Var);
                parcel2.writeNoException();
                return true;
            case 9:
                float fZze = zze();
                parcel2.writeNoException();
                parcel2.writeFloat(fZze);
                return true;
            case 10:
                boolean zO = o();
                parcel2.writeNoException();
                ClassLoader classLoader2 = AbstractC2857y5.a;
                parcel2.writeInt(zO ? 1 : 0);
                return true;
            case 11:
                w0 w0VarZzi = zzi();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, w0VarZzi);
                return true;
            case 12:
                boolean zX = x();
                parcel2.writeNoException();
                ClassLoader classLoader3 = AbstractC2857y5.a;
                parcel2.writeInt(zX ? 1 : 0);
                return true;
            case 13:
                m();
                parcel2.writeNoException();
                return true;
            default:
                return false;
        }
    }
}
