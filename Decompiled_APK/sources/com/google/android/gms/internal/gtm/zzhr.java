package com.google.android.gms.internal.gtm;

import android.os.RemoteException;
import java.util.Map;

/* loaded from: classes2.dex */
final class zzhr implements zzmx {
    final /* synthetic */ zzhv zza;

    public /* synthetic */ zzhr(zzhv zzhvVar, zzhu zzhuVar) {
        this.zza = zzhvVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzmx
    public final Object zza(String str, Map map) {
        try {
            this.zza.zze.zzc(str, map);
            return null;
        } catch (RemoteException e) {
            zzhi.zza("Error calling customEvaluator proxy:".concat(String.valueOf(e.getMessage())));
            return null;
        }
    }
}
