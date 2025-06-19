package com.quizlet.api.di;

import com.quizlet.api.okhttp.interceptors.DeviceIdInterceptor;
import dagger.internal.c;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class InterceptorModule_ProvideDeviceIdInterceptorFactory implements c {
    private final c deviceIdProvider;

    @Override // javax.inject.a
    public DeviceIdInterceptor get() {
        String deviceId = (String) this.deviceIdProvider.get();
        Intrinsics.checkNotNullParameter(deviceId, "deviceId");
        return new DeviceIdInterceptor(deviceId);
    }
}
