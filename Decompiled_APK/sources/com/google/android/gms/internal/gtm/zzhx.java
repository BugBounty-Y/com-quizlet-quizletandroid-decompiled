package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzhx {
    private zzhx zza;
    private Map zzb;

    private zzhx(zzhx zzhxVar) {
        this.zzb = null;
        this.zza = zzhxVar;
    }

    public final zzhx zza() {
        return new zzhx(this);
    }

    public final zzqo zzb(String str) {
        Map map = this.zzb;
        if (map != null && map.containsKey(str)) {
            return (zzqo) this.zzb.get(str);
        }
        zzhx zzhxVar = this.zza;
        if (zzhxVar != null) {
            return zzhxVar.zzb(str);
        }
        throw new IllegalStateException("Trying to get a non existent symbol: ".concat(String.valueOf(str)));
    }

    public final void zzc(String str, zzqo zzqoVar) {
        if (this.zzb == null) {
            this.zzb = new HashMap();
        }
        this.zzb.put(str, zzqoVar);
    }

    public final void zzd(String str) {
        u.k(zzf("gtm.globals.eventName"));
        Map map = this.zzb;
        if (map == null || !map.containsKey("gtm.globals.eventName")) {
            this.zza.zzd("gtm.globals.eventName");
        } else {
            this.zzb.remove("gtm.globals.eventName");
        }
    }

    public final void zze(String str, zzqo zzqoVar) {
        Map map = this.zzb;
        if (map != null && map.containsKey(str)) {
            this.zzb.put(str, zzqoVar);
            return;
        }
        zzhx zzhxVar = this.zza;
        if (zzhxVar == null) {
            throw new IllegalStateException("Trying to modify a non existent symbol: ".concat(String.valueOf(str)));
        }
        zzhxVar.zze(str, zzqoVar);
    }

    public final boolean zzf(String str) {
        Map map = this.zzb;
        if (map != null && map.containsKey(str)) {
            return true;
        }
        zzhx zzhxVar = this.zza;
        if (zzhxVar != null) {
            return zzhxVar.zzf(str);
        }
        return false;
    }

    public zzhx() {
        this(null);
    }
}
