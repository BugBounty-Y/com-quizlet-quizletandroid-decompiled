package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import java.util.Collections;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzqb {
    private final Map zza;
    private final zzqk zzb;

    public /* synthetic */ zzqb(Map map, zzqk zzqkVar, zzqa zzqaVar) {
        this.zza = Collections.unmodifiableMap(map);
        this.zzb = zzqkVar;
    }

    public final String toString() {
        return a.m("Properties: ", String.valueOf(this.zza), " pushAfterEvaluate: ", String.valueOf(this.zzb));
    }

    public final Map zza() {
        return this.zza;
    }
}
