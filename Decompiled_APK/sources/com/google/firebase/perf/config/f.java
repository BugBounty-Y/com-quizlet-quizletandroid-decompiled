package com.google.firebase.perf.config;

import com.google.android.gms.internal.mlkit_vision_common.D4;
import java.util.Collections;
import java.util.Map;

/* loaded from: classes2.dex */
public final class f extends D4 {
    public static f b;
    public static final Map c;

    static {
        androidx.camera.core.processing.n nVar = new androidx.camera.core.processing.n();
        nVar.put(461L, "FIREPERF_AUTOPUSH");
        nVar.put(462L, "FIREPERF");
        nVar.put(675L, "FIREPERF_INTERNAL_LOW");
        nVar.put(676L, "FIREPERF_INTERNAL_HIGH");
        c = Collections.unmodifiableMap(nVar);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.D4
    public final String a() {
        return "com.google.firebase.perf.LogSourceName";
    }
}
