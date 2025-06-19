package io.ktor.client.plugins;

import com.amazon.device.ads.DtbDeviceDataRetriever;
import java.io.IOException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.InterfaceC5037v;

@Metadata
/* loaded from: classes3.dex */
public final class HttpRequestTimeoutException extends IOException implements InterfaceC5037v {
    public final String a;
    public final Long b;

    public HttpRequestTimeoutException(String url, Long l, Throwable th) {
        Intrinsics.checkNotNullParameter(url, "url");
        StringBuilder sb = new StringBuilder("Request timeout has expired [url=");
        sb.append(url);
        sb.append(", request_timeout=");
        super(android.support.v4.media.session.a.s(sb, l == null ? DtbDeviceDataRetriever.ORIENTATION_UNKNOWN : l, " ms]"), th);
        this.a = url;
        this.b = l;
    }

    @Override // kotlinx.coroutines.InterfaceC5037v
    public final Throwable a() {
        return new HttpRequestTimeoutException(this.a, this.b, getCause());
    }
}
