package com.quizlet.api.okhttp.interceptors;

import com.quizlet.remote.model.notes.e;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.H;
import okhttp3.internal.http.f;
import okhttp3.t;
import okhttp3.u;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class DeviceIdInterceptor implements u {

    @NotNull
    private final String deviceId;

    public DeviceIdInterceptor(String deviceId) {
        Intrinsics.checkNotNullParameter(deviceId, "deviceId");
        this.deviceId = deviceId;
    }

    @Override // okhttp3.u
    public final H intercept(t chain) {
        Intrinsics.checkNotNullParameter(chain, "chain");
        f fVar = (f) chain;
        e eVarB = fVar.e.b();
        eVarB.h("X-QUIZLET-DEVICE-ID", this.deviceId);
        return fVar.b(eVarB.i());
    }
}
