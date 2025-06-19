package com.quizlet.login.intro.viewmodel;

import android.content.Intent;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.appsflyer.AppsFlyerLib;
import com.features.flashcards.creatormarketing.h;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.login.authentication.i;
import com.quizlet.login.common.interactors.data.k;
import com.quizlet.login.common.interactors.data.l;
import com.quizlet.login.common.interactors.data.m;
import com.quizlet.login.common.interactors.data.n;
import com.quizlet.login.common.interactors.data.p;
import com.quizlet.login.common.interactors.data.q;
import com.quizlet.login.common.interactors.data.s;
import com.quizlet.login.common.interactors.data.t;
import com.quizlet.login.common.interactors.data.v;
import com.quizlet.login.common.interactors.data.w;
import com.quizlet.login.common.interactors.data.x;
import com.quizlet.login.common.interactors.data.y;
import com.quizlet.login.common.interactors.data.z;
import com.quizlet.login.intro.data.f;
import com.quizlet.login.intro.data.g;
import com.quizlet.login.intro.data.j;
import com.quizlet.login.intro.data.o;
import com.quizlet.login.intro.data.r;
import com.quizlet.login.intro.data.u;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class e extends w0 implements a {
    public final h b;
    public final com.quizlet.analytics.marketing.appsflyer.b c;
    public final dagger.internal.a d;
    public final com.quizlet.login.common.util.b e;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e f;
    public final com.google.android.gms.internal.appset.e g;
    public final com.quizlet.data.interactor.progress.c h;
    public final dagger.internal.a i;
    public final m0 j;
    public final Intent k;
    public final d0 l;
    public final s0 m;

    public e(h signupLoginEventLogger, com.quizlet.analytics.marketing.appsflyer.b marketingAnalyticsDeepLinking, dagger.internal.a debugHostOverridePrefs, com.quizlet.login.common.util.b ageUtil, com.quizlet.data.repository.folderwithcreatorinclass.e compatibilityCheckerManager, com.google.android.gms.internal.appset.e logger, com.quizlet.data.interactor.progress.c signInWithGoogleUseCase, dagger.internal.a magicLinkSignInUseCase, m0 savedStateHandle) {
        Intrinsics.checkNotNullParameter(signupLoginEventLogger, "signupLoginEventLogger");
        Intrinsics.checkNotNullParameter(marketingAnalyticsDeepLinking, "marketingAnalyticsDeepLinking");
        Intrinsics.checkNotNullParameter(debugHostOverridePrefs, "debugHostOverridePrefs");
        Intrinsics.checkNotNullParameter(ageUtil, "ageUtil");
        Intrinsics.checkNotNullParameter(compatibilityCheckerManager, "compatibilityCheckerManager");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(signInWithGoogleUseCase, "signInWithGoogleUseCase");
        Intrinsics.checkNotNullParameter(magicLinkSignInUseCase, "magicLinkSignInUseCase");
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        this.b = signupLoginEventLogger;
        this.c = marketingAnalyticsDeepLinking;
        this.d = debugHostOverridePrefs;
        this.e = ageUtil;
        this.f = compatibilityCheckerManager;
        this.g = logger;
        this.h = signInWithGoogleUseCase;
        this.i = magicLinkSignInUseCase;
        this.j = savedStateHandle;
        this.k = (Intent) savedStateHandle.a("intent");
        this.l = e0.b(0, 1, null, 5);
        this.m = e0.c(new u(null, false, null, null, false));
    }

    public static final void A(e eVar, z zVar) {
        Object value;
        Object value2;
        Object value3;
        Object value4;
        eVar.getClass();
        boolean z = zVar instanceof l;
        s0 s0Var = eVar.m;
        if (z) {
            com.quizlet.login.authentication.data.b bVar = ((l) zVar).a;
            if (bVar.a == null) {
                eVar.B(true);
                return;
            } else {
                do {
                    value4 = s0Var.getValue();
                } while (!s0Var.k(value4, u.a((u) value4, null, new com.quizlet.login.authentication.b(bVar.a), false, 23)));
                return;
            }
        }
        if (Intrinsics.b(zVar, m.a)) {
            do {
                value3 = s0Var.getValue();
            } while (!s0Var.k(value3, u.a((u) value3, null, com.quizlet.login.authentication.c.c, false, 23)));
            return;
        }
        if (zVar instanceof n) {
            eVar.B(((n) zVar).a);
            return;
        }
        boolean zB = Intrinsics.b(zVar, p.a);
        d0 d0Var = eVar.l;
        if (zB) {
            d0Var.h(com.quizlet.login.intro.data.m.a);
            return;
        }
        if (Intrinsics.b(zVar, q.a)) {
            do {
                value2 = s0Var.getValue();
            } while (!s0Var.k(value2, u.a((u) value2, null, i.c, false, 23)));
            return;
        }
        if (zVar instanceof com.quizlet.login.common.interactors.data.u) {
            com.quizlet.login.common.interactors.data.u uVar = (com.quizlet.login.common.interactors.data.u) zVar;
            d0Var.h(new o(uVar.a, uVar.b));
            return;
        }
        if (zVar instanceof k) {
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, u.a((u) value, null, com.quizlet.login.authentication.a.c, false, 23)));
            return;
        }
        if (Intrinsics.b(zVar, w.a)) {
            d0Var.h(com.quizlet.login.intro.data.l.a);
            return;
        }
        if (Intrinsics.b(zVar, x.a)) {
            d0Var.h(r.a);
            return;
        }
        if (!Intrinsics.b(zVar, t.a) && !Intrinsics.b(zVar, s.a) && !Intrinsics.b(zVar, com.quizlet.login.common.interactors.data.o.a) && !(zVar instanceof v) && !(zVar instanceof com.quizlet.login.common.interactors.data.r) && !(zVar instanceof y)) {
            throw new NoWhenBranchMatchedException();
        }
        timber.log.c.a.p(new kotlin.n(e.class.getName() + " " + zVar));
    }

    public final void B(boolean z) {
        s0 s0Var;
        Object value;
        if (z) {
            do {
                s0Var = this.m;
                value = s0Var.getValue();
            } while (!s0Var.k(value, u.a((u) value, null, com.quizlet.login.authentication.h.c, false, 23)));
        }
    }

    public final void C(j event) {
        Object value;
        Object value2;
        Object value3;
        Intrinsics.checkNotNullParameter(event, "event");
        boolean zB = Intrinsics.b(event, com.quizlet.login.intro.data.b.a);
        d0 d0Var = this.l;
        h hVar = this.b;
        if (zB) {
            d0Var.h(com.quizlet.login.intro.data.p.a);
            EventLoggerExt.c(hVar.a, new com.quizlet.quizletandroid.ui.login.z(3));
            this.g.r(OTVendorListMode.GOOGLE, false);
            return;
        }
        if (Intrinsics.b(event, com.quizlet.login.intro.data.a.a)) {
            EventLoggerExt.c(hVar.a, new com.quizlet.quizletandroid.ui.login.z(1));
            d0Var.h(com.quizlet.login.intro.data.q.a);
            return;
        }
        boolean zB2 = Intrinsics.b(event, com.quizlet.login.intro.data.c.a);
        s0 s0Var = this.m;
        if (zB2) {
            do {
                value3 = s0Var.getValue();
            } while (!s0Var.k(value3, u.a((u) value3, null, null, false, 23)));
            return;
        }
        if (Intrinsics.b(event, com.quizlet.login.intro.data.i.a)) {
            d0Var.h(new com.quizlet.login.intro.data.s(com.quizlet.ui.models.webpage.l.c));
            return;
        }
        if (Intrinsics.b(event, f.a)) {
            d0Var.h(new com.quizlet.login.intro.data.s(com.quizlet.ui.models.webpage.i.c));
            return;
        }
        if (Intrinsics.b(event, com.quizlet.login.intro.data.e.a)) {
            d0Var.h(com.quizlet.login.intro.data.n.a);
            EventLoggerExt.c(hVar.a, new com.quizlet.quizletandroid.ui.login.z(4));
            return;
        }
        if (Intrinsics.b(event, com.quizlet.login.intro.data.d.a)) {
            assistantMode.refactored.a.p(((com.quizlet.quizletandroid.lib.a) this.d.get()).a, "PREFS_USE_HOST_OVERRIDE", false);
            do {
                value2 = s0Var.getValue();
            } while (!s0Var.k(value2, u.a((u) value2, null, null, false, 28)));
        } else if (event instanceof g) {
            E.A(p0.j(this), null, null, new c(this, ((g) event).a, null), 3);
        } else {
            if (!(event instanceof com.quizlet.login.intro.data.h)) {
                throw new NoWhenBranchMatchedException();
            }
            timber.log.c.a.p(((com.quizlet.login.intro.data.h) event).a);
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, u.a((u) value, null, com.quizlet.login.authentication.f.c, false, 23)));
        }
    }

    public final void D(boolean z) {
        s0 s0Var;
        Object value;
        do {
            s0Var = this.m;
            value = s0Var.getValue();
        } while (!s0Var.k(value, u.a((u) value, null, null, z, 15)));
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        this.c.getClass();
        AppsFlyerLib.getInstance().subscribeForDeepLink(null);
    }
}
