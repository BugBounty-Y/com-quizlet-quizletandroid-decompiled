package com.google.android.gms.internal.gtm;

import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzqk {
    private static final String zza = new String("");
    private final int zzb;
    private final Object zzc;
    private final List zzd;

    public /* synthetic */ zzqk(Integer num, Object obj, List list, boolean z, zzqj zzqjVar) {
        this.zzb = num.intValue();
        this.zzc = obj;
        this.zzd = Collections.unmodifiableList(list);
    }

    public final boolean equals(Object obj) {
        return (obj instanceof zzqk) && ((zzqk) obj).zzc.equals(this.zzc);
    }

    public final int hashCode() {
        return this.zzc.hashCode();
    }

    public final String toString() {
        Object obj = this.zzc;
        if (obj != null) {
            return obj.toString();
        }
        zzhi.zza("Fail to convert a null object to string");
        return zza;
    }

    public final int zza() {
        return this.zzb;
    }

    public final Object zzb() {
        return this.zzc;
    }

    public final List zzc() {
        return this.zzd;
    }
}
