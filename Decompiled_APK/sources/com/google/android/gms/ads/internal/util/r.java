package com.google.android.gms.ads.internal.util;

import android.os.Parcel;
import com.google.android.gms.ads.internal.offline.buffering.zza;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.ads.AbstractC2857y5;

/* loaded from: classes2.dex */
public final class r extends AbstractC2771w5 implements s {
    @Override // com.google.android.gms.ads.internal.util.s
    public final void zze(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(2, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.util.s
    public final boolean zzf(com.google.android.gms.dynamic.a aVar, String str, String str2) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        Parcel parcelY3 = Y3(1, parcelF3);
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.ads.internal.util.s
    public final boolean zzg(com.google.android.gms.dynamic.a aVar, zza zzaVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzaVar);
        Parcel parcelY3 = Y3(3, parcelF3);
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }
}
