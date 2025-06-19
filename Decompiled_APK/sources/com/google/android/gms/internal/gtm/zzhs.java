package com.google.android.gms.internal.gtm;

import android.os.RemoteException;
import java.util.Map;

/* loaded from: classes2.dex */
final class zzhs implements zzmx {
    final /* synthetic */ zzhv zza;

    public /* synthetic */ zzhs(zzhv zzhvVar, zzhu zzhuVar) {
        this.zza = zzhvVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzmx
    public final Object zza(String str, Map map) {
        try {
            return this.zza.zze.zzb(str, map);
        } catch (RemoteException e) {
            zzhi.zza("Error calling customEvaluator proxy:".concat(String.valueOf(e.getMessage())));
            return null;
        }
    }
}
