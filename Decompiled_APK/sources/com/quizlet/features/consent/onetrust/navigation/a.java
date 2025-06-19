package com.quizlet.features.consent.onetrust.navigation;

import androidx.fragment.app.I;
import com.quizlet.features.consent.onetrust.d;
import com.quizlet.features.infra.navigation.e;
import com.quizlet.learn.ads.g;
import com.quizlet.quizletandroid.ui.globalnav.composable.n;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements e {
    public final javax.inject.a a;

    public a(javax.inject.a oneTrustConsentManager) {
        Intrinsics.checkNotNullParameter(oneTrustConsentManager, "oneTrustConsentManager");
        this.a = oneTrustConsentManager;
    }

    @Override // com.quizlet.features.infra.navigation.e
    public final void d(I activity, g gVar, n nVar) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        if (com.quizlet.features.consent.onetrust.a.b || !((d) this.a.get()).b(activity, gVar)) {
            nVar.invoke();
        }
    }
}
