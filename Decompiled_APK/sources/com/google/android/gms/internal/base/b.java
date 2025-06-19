package com.google.android.gms.internal.base;

import com.google.android.gms.common.Feature;

/* loaded from: classes2.dex */
public abstract class b {
    public static final Feature a;
    public static final Feature[] b;
    public static final Feature c;
    public static final Feature[] d;

    static {
        Feature feature = new Feature("CLIENT_TELEMETRY", 1L);
        a = feature;
        b = new Feature[]{feature};
        Feature feature2 = new Feature("moduleinstall", 7L);
        c = feature2;
        d = new Feature[]{feature2};
    }
}
