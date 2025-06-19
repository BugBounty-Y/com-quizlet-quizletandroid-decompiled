package com.google.android.gms.analytics;

import android.net.Uri;

/* loaded from: classes2.dex */
public final class e implements k {
    public static final Uri a;

    static {
        Uri.Builder builder = new Uri.Builder();
        builder.scheme("uri");
        builder.authority("local");
        a = builder.build();
    }

    @Override // com.google.android.gms.analytics.k
    public final Uri zzb() {
        return a;
    }
}
