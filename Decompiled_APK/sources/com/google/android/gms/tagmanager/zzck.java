package com.google.android.gms.tagmanager;

import android.os.Bundle;
import android.os.IInterface;
import android.os.RemoteException;
import java.util.Map;

/* loaded from: classes2.dex */
public interface zzck extends IInterface {
    Map zzb() throws RemoteException;

    void zzc(String str, String str2, Bundle bundle, long j) throws RemoteException;

    void zzd(zzce zzceVar) throws RemoteException;

    void zze(zzch zzchVar) throws RemoteException;
}
