package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public abstract class zzqo {
    protected Map zza;

    public abstract String toString();

    public zzjm zza(String str) {
        throw new IllegalStateException(a.B("Attempting to access Native Method ", str, " on unsupported type."));
    }

    public zzqo zzb(String str) {
        Map map = this.zza;
        return map != null ? (zzqo) map.get(str) : zzqs.zze;
    }

    public abstract Object zzc();

    public final Iterator zzd() {
        Map map = this.zza;
        return map == null ? new zzqm(null) : new zzql(this, map.keySet().iterator());
    }

    public Iterator zze() {
        return new zzqm(null);
    }

    public final void zzf(String str, zzqo zzqoVar) {
        if (this.zza == null) {
            this.zza = new HashMap();
        }
        this.zza.put(str, zzqoVar);
    }

    public boolean zzg(String str) {
        return false;
    }

    public final boolean zzh(String str) {
        Map map = this.zza;
        return map != null && map.containsKey(str);
    }
}
