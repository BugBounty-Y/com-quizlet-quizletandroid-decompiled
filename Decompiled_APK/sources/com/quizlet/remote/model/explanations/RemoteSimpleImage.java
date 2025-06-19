package com.quizlet.remote.model.explanations;

import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSimpleImage {
    public final String a;
    public final Integer b;
    public final Integer c;

    public RemoteSimpleImage(@InterfaceC4853h(name = "srcUrl") @NotNull String srcUrl, @InterfaceC4853h(name = OTUXParamsKeys.OT_UX_HEIGHT) Integer num, @InterfaceC4853h(name = OTUXParamsKeys.OT_UX_WIDTH) Integer num2) {
        Intrinsics.checkNotNullParameter(srcUrl, "srcUrl");
        this.a = srcUrl;
        this.b = num;
        this.c = num2;
    }
}
