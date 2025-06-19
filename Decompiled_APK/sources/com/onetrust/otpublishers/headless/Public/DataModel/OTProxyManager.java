package com.onetrust.otpublishers.headless.Public.DataModel;

import androidx.annotation.Keep;
import java.net.URL;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Keep
@Metadata
/* loaded from: classes2.dex */
public interface OTProxyManager {
    @Keep
    URL getProxyDomain(@NotNull OTProxyType oTProxyType);
}
