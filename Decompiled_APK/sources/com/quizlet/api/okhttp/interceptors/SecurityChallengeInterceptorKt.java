package com.quizlet.api.okhttp.interceptors;

import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SecurityChallengeInterceptorKt {

    @NotNull
    private static final String CHALLENGE_HEADER = "cf-mitigated";

    @NotNull
    private static final String CHALLENGE_VALUE = "challenge";
}
