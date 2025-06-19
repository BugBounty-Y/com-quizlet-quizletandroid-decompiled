package io.ktor.client.plugins;

import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3189k7;
import com.google.android.gms.internal.mlkit_vision_barcode.V6;
import java.net.SocketTimeoutException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class b0 {
    public static final org.slf4j.b a = AbstractC3189k7.d("io.ktor.client.plugins.HttpTimeout");

    static {
        V6.a("HttpTimeout", Z.h, new com.sdk.growthbook.utils.a(14));
    }

    public static final SocketTimeoutException a(io.ktor.client.request.d request, Throwable th) {
        Object obj;
        Intrinsics.checkNotNullParameter(request, "request");
        StringBuilder sb = new StringBuilder("Socket timeout has expired [url=");
        sb.append(request.a);
        sb.append(", socket_timeout=");
        Y y = (Y) request.a();
        if (y == null || (obj = y.c) == null) {
            obj = DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
        }
        sb.append(obj);
        sb.append("] ms");
        String message = sb.toString();
        Intrinsics.checkNotNullParameter(message, "message");
        SocketTimeoutException socketTimeoutException = new SocketTimeoutException(message);
        socketTimeoutException.initCause(th);
        return socketTimeoutException;
    }
}
