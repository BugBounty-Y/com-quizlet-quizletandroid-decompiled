package com.google.android.gms.tagmanager;

import android.content.Intent;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.dynamic.a;
import com.google.android.gms.dynamic.b;
import com.google.android.gms.internal.gtm.zzas;
import com.google.android.gms.internal.gtm.zzat;

/* loaded from: classes2.dex */
public abstract class zzcm extends zzas implements zzcn {
    public zzcm() {
        super("com.google.android.gms.tagmanager.ITagManagerApi");
    }

    public static zzcn asInterface(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.tagmanager.ITagManagerApi");
        return iInterfaceQueryLocalInterface instanceof zzcn ? (zzcn) iInterfaceQueryLocalInterface : new zzcl(iBinder);
    }

    @Override // com.google.android.gms.internal.gtm.zzas
    public final boolean zza(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        zzck zzciVar;
        zzck zzciVar2;
        zzcb zzbzVar = null;
        if (i == 1) {
            a aVarV3 = b.v3(parcel.readStrongBinder());
            IBinder strongBinder = parcel.readStrongBinder();
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
            initialize(aVarV3, zzciVar, zzbzVar);
        } else if (i == 2) {
            Intent intent = (Intent) zzat.zza(parcel, Intent.CREATOR);
            a aVarV32 = b.v3(parcel.readStrongBinder());
            zzat.zzc(parcel);
            preview(intent, aVarV32);
        } else {
            if (i != 3) {
                return false;
            }
            Intent intent2 = (Intent) zzat.zza(parcel, Intent.CREATOR);
            a aVarV33 = b.v3(parcel.readStrongBinder());
            a aVarV34 = b.v3(parcel.readStrongBinder());
            IBinder strongBinder3 = parcel.readStrongBinder();
            if (strongBinder3 == null) {
                zzciVar2 = null;
            } else {
                IInterface iInterfaceQueryLocalInterface3 = strongBinder3.queryLocalInterface("com.google.android.gms.tagmanager.IMeasurementProxy");
                zzciVar2 = iInterfaceQueryLocalInterface3 instanceof zzck ? (zzck) iInterfaceQueryLocalInterface3 : new zzci(strongBinder3);
            }
            IBinder strongBinder4 = parcel.readStrongBinder();
            if (strongBinder4 != null) {
                IInterface iInterfaceQueryLocalInterface4 = strongBinder4.queryLocalInterface("com.google.android.gms.tagmanager.ICustomEvaluatorProxy");
                zzbzVar = iInterfaceQueryLocalInterface4 instanceof zzcb ? (zzcb) iInterfaceQueryLocalInterface4 : new zzbz(strongBinder4);
            }
            zzcb zzcbVar = zzbzVar;
            zzat.zzc(parcel);
            previewIntent(intent2, aVarV33, aVarV34, zzciVar2, zzcbVar);
        }
        parcel2.writeNoException();
        return true;
    }
}
