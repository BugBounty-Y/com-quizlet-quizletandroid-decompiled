package com.google.android.gms.tagmanager;

import android.content.Context;
import android.os.RemoteException;
import com.google.android.gms.common.util.DynamiteApi;
import com.google.android.gms.dynamic.a;
import com.google.android.gms.dynamic.b;
import com.google.android.gms.internal.gtm.zzhg;
import com.google.android.gms.internal.gtm.zzjb;

@DynamiteApi
/* loaded from: classes2.dex */
public class TagManagerServiceProviderImpl extends zzcp {
    private static volatile zzjb zza;

    @Override // com.google.android.gms.tagmanager.zzcq
    public zzhg getService(a aVar, zzck zzckVar, zzcb zzcbVar) throws RemoteException {
        zzjb zzjbVar;
        zzjb zzjbVar2 = zza;
        if (zzjbVar2 != null) {
            return zzjbVar2;
        }
        synchronized (TagManagerServiceProviderImpl.class) {
            try {
                zzjbVar = zza;
                if (zzjbVar == null) {
                    zzjbVar = new zzjb((Context) b.I3(aVar), zzckVar, zzcbVar);
                    zza = zzjbVar;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return zzjbVar;
    }
}
