package com.quizlet.features.practicetest.navigation;

import android.content.Intent;
import com.quizlet.features.infra.navigation.C;
import com.quizlet.features.infra.navigation.D;
import com.quizlet.features.infra.navigation.m;
import com.quizlet.features.infra.navigation.q;
import com.quizlet.features.infra.navigation.t;
import com.quizlet.features.infra.navigation.w;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.W;

/* loaded from: classes3.dex */
public final class d implements C, w, t, D, m, q {
    public final /* synthetic */ C a;
    public final /* synthetic */ w b;
    public final /* synthetic */ t c;
    public final /* synthetic */ D d;
    public final /* synthetic */ m e;
    public final /* synthetic */ q f;

    public d(C userProfileNavigation, w shareSheetNavigation, t reportSubmittedNavigation, D webPageNavigation, m loginNavNavigation, q paywallNavigation) {
        Intrinsics.checkNotNullParameter(userProfileNavigation, "userProfileNavigation");
        Intrinsics.checkNotNullParameter(shareSheetNavigation, "shareSheetNavigation");
        Intrinsics.checkNotNullParameter(reportSubmittedNavigation, "reportSubmittedNavigation");
        Intrinsics.checkNotNullParameter(webPageNavigation, "webPageNavigation");
        Intrinsics.checkNotNullParameter(loginNavNavigation, "loginNavNavigation");
        Intrinsics.checkNotNullParameter(paywallNavigation, "paywallNavigation");
        this.a = userProfileNavigation;
        this.b = shareSheetNavigation;
        this.c = reportSubmittedNavigation;
        this.d = webPageNavigation;
        this.e = loginNavNavigation;
        this.f = paywallNavigation;
    }

    @Override // com.quizlet.features.infra.navigation.D
    public final void D(com.quizlet.ui.models.webpage.m webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        this.d.D(webPage);
    }

    @Override // com.quizlet.features.infra.navigation.D
    public final void H() {
        this.d.H();
    }

    @Override // com.quizlet.features.infra.navigation.t
    public final W a() {
        return this.c.a();
    }

    @Override // com.quizlet.features.infra.navigation.q
    public final void b(String upgradeSource, com.quizlet.features.infra.models.upgrade.a navigationSource) {
        Intrinsics.checkNotNullParameter(upgradeSource, "upgradeSource");
        Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
        this.f.b(upgradeSource, navigationSource);
    }

    @Override // com.quizlet.features.infra.navigation.w
    public final void c(com.quizlet.features.infra.models.share.a request) {
        Intrinsics.checkNotNullParameter(request, "request");
        this.b.c(request);
    }

    @Override // com.quizlet.features.infra.navigation.m
    public final void j(Intent intent) {
        this.e.j(intent);
    }

    @Override // com.quizlet.features.infra.navigation.D
    public final void p(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        this.d.p(url);
    }

    @Override // com.quizlet.features.infra.navigation.m
    public final void r(Intent intent) {
        this.e.r(intent);
    }

    @Override // com.quizlet.features.infra.navigation.m
    public final void x(String code) {
        Intrinsics.checkNotNullParameter(code, "code");
        this.e.x(code);
    }

    @Override // com.quizlet.features.infra.navigation.C
    public final void y(long j) {
        this.a.y(j);
    }
}
