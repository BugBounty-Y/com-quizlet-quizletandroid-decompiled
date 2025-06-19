package com.google.android.gms.internal.gtm;

import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;

/* loaded from: classes2.dex */
public abstract class zzhf extends zzas implements zzhg {
    public zzhf() {
        super("com.google.android.gms.tagmanager.internal.ITagManagerService");
    }

    public static zzhg zzb(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.tagmanager.internal.ITagManagerService");
        return iInterfaceQueryLocalInterface instanceof zzhg ? (zzhg) iInterfaceQueryLocalInterface : new zzhe(iBinder);
    }

    @Override // com.google.android.gms.internal.gtm.zzas
    public final boolean zza(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        zzhd zzhbVar;
        if (i == 1) {
            String string = parcel.readString();
            String string2 = parcel.readString();
            String string3 = parcel.readString();
            zzat.zzc(parcel);
            zzg(string, string2, string3);
        } else if (i == 2) {
            String string4 = parcel.readString();
            String string5 = parcel.readString();
            String string6 = parcel.readString();
            IBinder strongBinder = parcel.readStrongBinder();
            if (strongBinder == null) {
                zzhbVar = null;
            } else {
                IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.tagmanager.internal.ITagManagerLoadContainerCallback");
                zzhbVar = iInterfaceQueryLocalInterface instanceof zzhd ? (zzhd) iInterfaceQueryLocalInterface : new zzhb(strongBinder);
            }
            zzat.zzc(parcel);
            zzh(string4, string5, string6, zzhbVar);
        } else if (i == 3) {
            zzi();
        } else if (i == 101) {
            String string7 = parcel.readString();
            Bundle bundle = (Bundle) zzat.zza(parcel, Bundle.CREATOR);
            String string8 = parcel.readString();
            long j = parcel.readLong();
            boolean zZzf = zzat.zzf(parcel);
            zzat.zzc(parcel);
            zzf(string7, bundle, string8, j, zZzf);
        } else {
            if (i != 102) {
                return false;
            }
            zze();
        }
        parcel2.writeNoException();
        return true;
    }
}
