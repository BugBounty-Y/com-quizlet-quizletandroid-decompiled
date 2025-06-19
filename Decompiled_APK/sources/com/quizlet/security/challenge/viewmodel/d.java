package com.quizlet.security.challenge.viewmodel;

import android.webkit.CookieManager;
import androidx.lifecycle.w0;
import androidx.recyclerview.widget.C1372j;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K6;
import com.quizlet.data.model.C4184z;
import com.quizlet.data.repository.set.f;
import com.quizlet.data.repository.studysetwithcreatorinclass.g;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class d extends w0 {
    public final g b;
    public final com.quizlet.usecase.b c;
    public final com.quizlet.features.emailconfirmation.logging.a d;
    public final f e;
    public final String f;
    public final a g;
    public final d0 h;
    public final s0 i;

    public d(g cookieManager, com.quizlet.usecase.b challengeDetected, com.quizlet.features.emailconfirmation.logging.a eventLogger, C4184z buildConfigProvider, f nightThemeManager) {
        Intrinsics.checkNotNullParameter(cookieManager, "cookieManager");
        Intrinsics.checkNotNullParameter(challengeDetected, "challengeDetected");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(buildConfigProvider, "buildConfigProvider");
        Intrinsics.checkNotNullParameter(nightThemeManager, "nightThemeManager");
        this.b = cookieManager;
        this.c = challengeDetected;
        this.d = eventLogger;
        this.e = nightThemeManager;
        Intrinsics.checkNotNullParameter(buildConfigProvider, "<this>");
        buildConfigProvider.getClass();
        this.f = K6.a("9.34.3");
        this.g = new a(new com.quizlet.security.challenge.ui.b(0, this, d.class, "onChallengeSolved", "onChallengeSolved()V", 0, 1));
        this.h = e0.b(0, 1, null, 5);
        this.i = e0.c(Boolean.FALSE);
        eventLogger.b(com.quizlet.security.challenge.eventlogging.b.b);
    }

    public final String A() {
        Intrinsics.checkNotNullParameter("https://www.quizlet.com/cf-challenge", "<this>");
        C1372j c1372j = new C1372j();
        c1372j.l(null, "https://www.quizlet.com/cf-challenge");
        C1372j c1372jF = c1372j.d().f();
        boolean zQ = this.e.q();
        Intrinsics.checkNotNullParameter(c1372jF, "<this>");
        c1372jF.c("__injectedColorTheme", zQ ? "night" : "default");
        return c1372jF.toString();
    }

    public final void B() {
        String url = A();
        g gVar = this.b;
        gVar.getClass();
        Intrinsics.checkNotNullParameter(url, "url");
        try {
            gVar.r(CookieManager.getInstance().getCookie(url));
        } catch (Exception e) {
            timber.log.c.a.f(e, "Failed to get cookies from Security Challenge WebView", new Object[0]);
        }
        ((com.quizlet.usecase.a) this.c).a(Boolean.FALSE);
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        this.d.b(com.quizlet.security.challenge.eventlogging.a.b);
    }
}
