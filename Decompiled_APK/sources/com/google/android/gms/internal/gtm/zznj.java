package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.telephony.TelephonyManager;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zznj implements zzjm {
    private final Context zza;

    public zznj(Context context) {
        u.h(context);
        this.zza = context;
    }

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        String networkOperatorName;
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 0);
        TelephonyManager telephonyManager = (TelephonyManager) this.zza.getSystemService("phone");
        zzqs zzqsVar = zzqs.zze;
        return (telephonyManager == null || (networkOperatorName = telephonyManager.getNetworkOperatorName()) == null) ? zzqsVar : new zzqz(networkOperatorName);
    }
}
