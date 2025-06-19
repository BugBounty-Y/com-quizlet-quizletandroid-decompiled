package com.quizlet.features.blocks;

import androidx.lifecycle.m0;
import androidx.lifecycle.w0;
import com.quizlet.data.model.C4184z;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

@Metadata
/* loaded from: classes2.dex */
public final class g extends w0 {
    public final String b;
    public final String c;
    public final String d;
    public final d0 e;

    public g(m0 savedStateHandle, com.quizlet.data.token.a accessTokenProvider, C4184z buildConfig) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(accessTokenProvider, "accessTokenProvider");
        Intrinsics.checkNotNullParameter(buildConfig, "buildConfig");
        Object objA = savedStateHandle.a("url_extra");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.b = (String) objA;
        this.c = "9.34.3";
        String strA = accessTokenProvider.a();
        this.d = strA == null ? "" : strA;
        this.e = e0.b(0, 0, null, 7);
    }
}
