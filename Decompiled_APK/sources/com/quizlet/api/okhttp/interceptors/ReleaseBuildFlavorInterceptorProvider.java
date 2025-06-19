package com.quizlet.api.okhttp.interceptors;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.z;

@Metadata
/* loaded from: classes2.dex */
public final class ReleaseBuildFlavorInterceptorProvider implements BuildFlavorInterceptorProvider {
    @Override // com.quizlet.api.okhttp.interceptors.BuildFlavorInterceptorProvider
    public final z a(z builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        return builder;
    }
}
