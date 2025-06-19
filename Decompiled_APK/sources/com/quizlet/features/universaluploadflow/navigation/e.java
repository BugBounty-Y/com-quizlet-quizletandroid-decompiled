package com.quizlet.features.universaluploadflow.navigation;

import android.content.Intent;
import com.quizlet.data.model.U0;
import com.quizlet.features.infra.navigation.D;
import com.quizlet.features.infra.navigation.m;
import com.quizlet.features.infra.navigation.q;
import com.quizlet.features.infra.navigation.r;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements D, r, q, m {
    public final /* synthetic */ D a;
    public final /* synthetic */ r b;
    public final /* synthetic */ q c;
    public final /* synthetic */ m d;

    public e(D webPageNavigation, r practiceTesNavigation, q paywallNavigation, m loginNavNavigation) {
        Intrinsics.checkNotNullParameter(webPageNavigation, "webPageNavigation");
        Intrinsics.checkNotNullParameter(practiceTesNavigation, "practiceTesNavigation");
        Intrinsics.checkNotNullParameter(paywallNavigation, "paywallNavigation");
        Intrinsics.checkNotNullParameter(loginNavNavigation, "loginNavNavigation");
        this.a = webPageNavigation;
        this.b = practiceTesNavigation;
        this.c = paywallNavigation;
        this.d = loginNavNavigation;
    }

    @Override // com.quizlet.features.infra.navigation.D
    public final void D(com.quizlet.ui.models.webpage.m webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        this.a.D(webPage);
    }

    @Override // com.quizlet.features.infra.navigation.D
    public final void H() {
        this.a.H();
    }

    @Override // com.quizlet.features.infra.navigation.q
    public final void b(String upgradeSource, com.quizlet.features.infra.models.upgrade.a navigationSource) {
        Intrinsics.checkNotNullParameter(upgradeSource, "upgradeSource");
        Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
        this.c.b(upgradeSource, navigationSource);
    }

    @Override // com.quizlet.features.infra.navigation.r
    public final void g(String questionBankUuid) {
        U0 origin = U0.e;
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        Intrinsics.checkNotNullParameter(origin, "origin");
        this.b.g(questionBankUuid);
    }

    @Override // com.quizlet.features.infra.navigation.m
    public final void j(Intent intent) {
        this.d.j(intent);
    }

    @Override // com.quizlet.features.infra.navigation.r
    public final void k(String questionBankUuid) {
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        this.b.k(questionBankUuid);
    }

    @Override // com.quizlet.features.infra.navigation.D
    public final void p(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        this.a.p(url);
    }

    @Override // com.quizlet.features.infra.navigation.m
    public final void r(Intent intent) {
        this.d.r(intent);
    }

    @Override // com.quizlet.features.infra.navigation.m
    public final void x(String code) {
        Intrinsics.checkNotNullParameter(code, "code");
        this.d.x(code);
    }
}
