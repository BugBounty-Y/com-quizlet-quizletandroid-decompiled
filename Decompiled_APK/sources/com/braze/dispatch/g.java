package com.braze.dispatch;

import androidx.lifecycle.C1247h;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.storage.z;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g {
    public final void a(BrazeConfigurationProvider configurationProvider, z sdkAuthenticationCache, com.braze.requests.n brazeRequest, String deviceId) {
        Intrinsics.checkNotNullParameter(configurationProvider, "configurationProvider");
        Intrinsics.checkNotNullParameter(sdkAuthenticationCache, "sdkAuthenticationCache");
        Intrinsics.checkNotNullParameter(brazeRequest, "brazeRequest");
        Intrinsics.checkNotNullParameter(deviceId, "deviceId");
        com.braze.requests.b bVar = (com.braze.requests.b) brazeRequest;
        bVar.e = deviceId;
        bVar.f = configurationProvider.getBrazeApiKey().a;
        bVar.g = "36.0.0";
        bVar.d = Long.valueOf(DateTimeUtils.nowInSeconds());
        if (!configurationProvider.isSdkAuthenticationEnabled()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.configuration.h(12), 6, (Object) null);
        } else {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new C1247h(sdkAuthenticationCache, 12), 6, (Object) null);
            bVar.i = sdkAuthenticationCache.d.getString("auth_signature", null);
        }
    }

    public static final String a(z zVar) {
        return "Adding SDK Auth token to request '" + zVar.d.getString("auth_signature", null) + '\'';
    }

    public static final String a() {
        return "SDK Auth is disabled, not adding signature to request";
    }
}
