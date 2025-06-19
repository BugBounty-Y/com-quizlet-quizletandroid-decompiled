package com.google.android.gms.appset;

import com.google.android.gms.common.Feature;

/* loaded from: classes2.dex */
public abstract class c {
    public static final Feature a;
    public static final Feature[] b;

    static {
        Feature feature = new Feature("app_set_id", 1L);
        a = feature;
        b = new Feature[]{feature};
    }
}
