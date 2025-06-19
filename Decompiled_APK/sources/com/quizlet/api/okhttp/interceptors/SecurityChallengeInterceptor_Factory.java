package com.quizlet.api.okhttp.interceptors;

import com.quizlet.usecase.b;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class SecurityChallengeInterceptor_Factory implements c {
    private final c securityChallengeDetectedProvider;
    private final c shouldShowChallengeProvider;

    @Override // javax.inject.a
    public SecurityChallengeInterceptor get() {
        return new SecurityChallengeInterceptor((b) this.shouldShowChallengeProvider.get(), (b) this.securityChallengeDetectedProvider.get());
    }
}
