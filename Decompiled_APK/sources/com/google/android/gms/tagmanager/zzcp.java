package com.google.android.gms.tagmanager;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.dynamic.a;
import com.google.android.gms.dynamic.b;
import com.google.android.gms.internal.gtm.zzas;
import com.google.android.gms.internal.gtm.zzat;
import com.google.android.gms.internal.gtm.zzhg;

/* loaded from: classes2.dex */
public abstract class zzcp extends zzas implements zzcq {
    public zzcp() {
        super("com.google.android.gms.tagmanager.ITagManagerServiceProvider");
    }

    public static zzcq asInterface(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.tagmanager.ITagManagerServiceProvider");
        return iInterfaceQueryLocalInterface instanceof zzcq ? (zzcq) iInterfaceQueryLocalInterface : new zzco(iBinder);
    }

    @Override // com.google.android.gms.internal.gtm.zzas
    public final boolean zza(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        zzck zzciVar;
        if (i != 1) {
            return false;
        }
        a aVarV3 = b.v3(parcel.readStrongBinder());
        IBinder strongBinder = parcel.readStrongBinder();
        zzcb zzbzVar = null;
        if (strongBinder == null) {
            zzciVar = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.tagmanager.IMeasurementProxy");
            zzciVar = iInterfaceQueryLocalInterface instanceof zzck ? (zzck) iInterfaceQueryLocalInterface : new zzci(strongBinder);
        }
        IBinder strongBinder2 = parcel.readStrongBinder();
        if (strongBinder2 != null) {
            IInterface iInterfaceQueryLocalInterface2 = strongBinder2.queryLocalInterface("com.google.android.gms.tagmanager.ICustomEvaluatorProxy");
            zzbzVar = iInterfaceQueryLocalInterface2 instanceof zzcb ? (zzcb) iInterfaceQueryLocalInterface2 : new zzbz(strongBinder2);
        }
        zzat.zzc(parcel);
        zzhg service = getService(aVarV3, zzciVar, zzbzVar);
        parcel2.writeNoException();
        zzat.zze(parcel2, service);
        return true;
    }
}
