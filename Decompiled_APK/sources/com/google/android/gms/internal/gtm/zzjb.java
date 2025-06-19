package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.os.Bundle;
import android.os.RemoteException;
import com.google.android.gms.common.internal.u;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;

/* loaded from: classes2.dex */
public final class zzjb extends zzhf {
    private final Map zza;
    private final ExecutorService zzb;
    private final zzgn zzc;
    private final com.google.android.gms.tagmanager.zzck zzd;
    private final Context zze;

    public zzjb(Context context, com.google.android.gms.tagmanager.zzck zzckVar, com.google.android.gms.tagmanager.zzcb zzcbVar) {
        zzgn zzgnVar = new zzgn(context, zzckVar, zzcbVar);
        ExecutorService executorServiceZza = zzjd.zza(context);
        this.zza = new HashMap(1);
        u.h(zzckVar);
        this.zzd = zzckVar;
        this.zzc = zzgnVar;
        this.zzb = executorServiceZza;
        this.zze = context;
    }

    @Override // com.google.android.gms.internal.gtm.zzhg
    public final void zze() {
        this.zzb.execute(new zzja(this));
    }

    @Override // com.google.android.gms.internal.gtm.zzhg
    public final void zzf(String str, Bundle bundle, String str2, long j, boolean z) throws RemoteException {
        this.zzb.execute(new zziz(this, new zzgt(str, bundle, str2, new Date(j), z, this.zzd)));
    }

    @Override // com.google.android.gms.internal.gtm.zzhg
    public final void zzg(String str, String str2, String str3) throws RemoteException {
        zzh(str, str2, str3, null);
    }

    @Override // com.google.android.gms.internal.gtm.zzhg
    public final void zzh(String str, String str2, String str3, zzhd zzhdVar) throws RemoteException {
        this.zzb.execute(new zziy(this, str, str2, str3, zzhdVar));
    }

    @Override // com.google.android.gms.internal.gtm.zzhg
    public final void zzi() throws RemoteException {
        this.zza.clear();
    }
}
