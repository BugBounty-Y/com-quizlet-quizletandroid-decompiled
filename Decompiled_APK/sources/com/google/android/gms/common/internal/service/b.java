package com.google.android.gms.common.internal.service;

import com.airbnb.lottie.network.d;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.e;
import com.google.android.gms.common.api.internal.k;
import com.google.android.gms.common.internal.TelemetryData;
import com.google.android.gms.internal.ads.AbstractC2027eu;
import com.google.android.gms.tasks.m;

/* loaded from: classes2.dex */
public final class b extends e {
    public static final com.quizlet.data.repository.activitycenter.b l = new com.quizlet.data.repository.activitycenter.b("ClientTelemetry.API", new com.google.android.gms.auth.api.b(2), new com.google.mlkit.common.sdkinternal.b(9));

    public final m d(TelemetryData telemetryData) {
        k kVarA = AbstractC2027eu.a();
        kVarA.e = new Feature[]{com.google.android.gms.internal.base.b.a};
        kVarA.c = false;
        kVarA.d = new d(telemetryData, 24);
        return c(2, kVarA.a());
    }
}
