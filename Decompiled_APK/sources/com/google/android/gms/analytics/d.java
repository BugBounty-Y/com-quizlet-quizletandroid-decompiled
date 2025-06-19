package com.google.android.gms.analytics;

import android.net.Uri;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.gtm.zzbq;
import com.google.android.gms.internal.gtm.zzbu;

/* loaded from: classes2.dex */
public final class d extends zzbq implements k {
    public final Uri a;

    public d(zzbu zzbuVar, String str) {
        super(zzbuVar);
        u.e(str);
        u.e(str);
        Uri.Builder builder = new Uri.Builder();
        builder.scheme("uri");
        builder.authority("google-analytics.com");
        builder.path(str);
        this.a = builder.build();
    }

    @Override // com.google.android.gms.analytics.k
    public final Uri zzb() {
        return this.a;
    }
}
