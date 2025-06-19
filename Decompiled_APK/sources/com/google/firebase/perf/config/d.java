package com.google.firebase.perf.config;

import com.google.android.gms.internal.mlkit_vision_common.D4;

/* loaded from: classes2.dex */
public final class d extends D4 {
    public static d b;

    public static synchronized d c() {
        try {
            if (b == null) {
                b = new d();
            }
        } catch (Throwable th) {
            throw th;
        }
        return b;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.D4
    public final String a() {
        return "com.google.firebase.perf.ExperimentTTID";
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.D4
    public final String b() {
        return "experiment_app_start_ttid";
    }
}
