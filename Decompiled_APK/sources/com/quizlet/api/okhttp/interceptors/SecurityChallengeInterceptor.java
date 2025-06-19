package com.quizlet.api.okhttp.interceptors;

import com.quizlet.usecase.a;
import com.quizlet.usecase.b;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.H;
import okhttp3.internal.http.f;
import okhttp3.t;
import okhttp3.u;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SecurityChallengeInterceptor implements u {

    @NotNull
    private final b securityChallengeDetected;

    @NotNull
    private final b shouldShowChallenge;

    public SecurityChallengeInterceptor(b shouldShowChallenge, b securityChallengeDetected) {
        Intrinsics.checkNotNullParameter(shouldShowChallenge, "shouldShowChallenge");
        Intrinsics.checkNotNullParameter(securityChallengeDetected, "securityChallengeDetected");
        this.shouldShowChallenge = shouldShowChallenge;
        this.securityChallengeDetected = securityChallengeDetected;
    }

    @Override // okhttp3.u
    public final H intercept(t chain) {
        Intrinsics.checkNotNullParameter(chain, "chain");
        f fVar = (f) chain;
        H hB = fVar.b(fVar.e);
        if (!hB.d() && Intrinsics.b(H.a("cf-mitigated", hB), "challenge")) {
            ((a) this.shouldShowChallenge).a(Boolean.TRUE);
            ((a) this.securityChallengeDetected).a(hB.a.a.b());
        }
        return hB;
    }
}
