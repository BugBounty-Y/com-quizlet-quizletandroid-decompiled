package com.google.android.gms.tagmanager;

import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.internal.gtm.zzas;
import com.google.android.gms.internal.gtm.zzat;
import java.util.Map;

/* loaded from: classes2.dex */
public abstract class zzcj extends zzas implements zzck {
    public zzcj() {
        super("com.google.android.gms.tagmanager.IMeasurementProxy");
    }

    @Override // com.google.android.gms.internal.gtm.zzas
    public final boolean zza(int i, Parcel parcel, Parcel parcel2, int i2) throws RemoteException {
        if (i == 2) {
            String string = parcel.readString();
            String string2 = parcel.readString();
            Bundle bundle = (Bundle) zzat.zza(parcel, Bundle.CREATOR);
            long j = parcel.readLong();
            zzat.zzc(parcel);
            zzc(string, string2, bundle, j);
            parcel2.writeNoException();
            return true;
        }
        if (i == 11) {
            Map mapZzb = zzb();
            parcel2.writeNoException();
            parcel2.writeMap(mapZzb);
            return true;
        }
        zzch zzcfVar = null;
        zzce zzccVar = null;
        if (i == 21) {
            IBinder strongBinder = parcel.readStrongBinder();
            if (strongBinder != null) {
                IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.tagmanager.IMeasurementInterceptor");
                zzcfVar = iInterfaceQueryLocalInterface instanceof zzch ? (zzch) iInterfaceQueryLocalInterface : new zzcf(strongBinder);
            }
            zzat.zzc(parcel);
            zze(zzcfVar);
            parcel2.writeNoException();
            return true;
        }
        if (i != 22) {
            return false;
        }
        IBinder strongBinder2 = parcel.readStrongBinder();
        if (strongBinder2 != null) {
            IInterface iInterfaceQueryLocalInterface2 = strongBinder2.queryLocalInterface("com.google.android.gms.tagmanager.IMeasurementEventListener");
            zzccVar = iInterfaceQueryLocalInterface2 instanceof zzce ? (zzce) iInterfaceQueryLocalInterface2 : new zzcc(strongBinder2);
        }
        zzat.zzc(parcel);
        zzd(zzccVar);
        parcel2.writeNoException();
        return true;
    }
}
