package com.quizlet.login.login.viewmodel;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.features.flashcards.creatormarketing.h;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.firebase.messaging.u;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.login.authentication.i;
import com.quizlet.login.authentication.j;
import com.quizlet.login.common.interactors.data.k;
import com.quizlet.login.common.interactors.data.l;
import com.quizlet.login.common.interactors.data.m;
import com.quizlet.login.common.interactors.data.n;
import com.quizlet.login.common.interactors.data.o;
import com.quizlet.login.common.interactors.data.q;
import com.quizlet.login.common.interactors.data.r;
import com.quizlet.login.common.interactors.data.s;
import com.quizlet.login.common.interactors.data.t;
import com.quizlet.login.common.interactors.data.v;
import com.quizlet.login.common.interactors.data.x;
import com.quizlet.login.common.interactors.data.y;
import com.quizlet.login.common.interactors.data.z;
import com.quizlet.login.login.data.g;
import com.quizlet.login.login.data.p;
import com.quizlet.login.login.data.w;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class f extends w0 implements a {
    public final h b;
    public final com.google.android.gms.internal.appset.e c;
    public final C1721Kc d;
    public final com.quizlet.data.interactor.progress.c e;
    public final u f;
    public final com.quizlet.data.repository.user.a g;
    public final s0 h;
    public final d0 i;

    public f(h signupLoginEventLogger, com.google.android.gms.internal.appset.e logger, C1721Kc signInWithEmailAndPasswordUseCase, com.quizlet.data.interactor.progress.c signInWithGoogleUseCase, u signInWithFacebookUseCase, com.quizlet.data.repository.user.a facebookSSOFeature) {
        Intrinsics.checkNotNullParameter(signupLoginEventLogger, "signupLoginEventLogger");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(signInWithEmailAndPasswordUseCase, "signInWithEmailAndPasswordUseCase");
        Intrinsics.checkNotNullParameter(signInWithGoogleUseCase, "signInWithGoogleUseCase");
        Intrinsics.checkNotNullParameter(signInWithFacebookUseCase, "signInWithFacebookUseCase");
        Intrinsics.checkNotNullParameter(facebookSSOFeature, "facebookSSOFeature");
        this.b = signupLoginEventLogger;
        this.c = logger;
        this.d = signInWithEmailAndPasswordUseCase;
        this.e = signInWithGoogleUseCase;
        this.f = signInWithFacebookUseCase;
        this.g = facebookSSOFeature;
        this.h = e0.c(new w(null, true, false, false, ""));
        this.i = e0.b(0, 1, null, 5);
        E.A(p0.j(this), null, null, new e(this, null), 3);
    }

    public static final void A(f fVar, z zVar) {
        s0 s0Var;
        Object value;
        fVar.getClass();
        if ((zVar instanceof com.quizlet.login.common.interactors.data.w) || (zVar instanceof x)) {
            return;
        }
        do {
            s0Var = fVar.h;
            value = s0Var.getValue();
        } while (!s0Var.k(value, w.a((w) value, null, false, false, false, null, 27)));
    }

    public static final void B(f fVar) {
        Object value;
        s0 s0Var = fVar.h;
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, w.a((w) value, null, false, true, false, null, 26)));
    }

    public final void C(z zVar, boolean z) {
        Object value;
        Object value2;
        Object value3;
        Object value4;
        Object value5;
        boolean z2 = zVar instanceof l;
        s0 s0Var = this.h;
        if (!z2) {
            if (Intrinsics.b(zVar, m.a)) {
                do {
                    value5 = s0Var.getValue();
                } while (!s0Var.k(value5, w.a((w) value5, com.quizlet.login.authentication.c.c, false, false, false, null, 30)));
                return;
            }
            if (zVar instanceof n) {
                D(((n) zVar).a);
                return;
            }
            if (Intrinsics.b(zVar, q.a)) {
                do {
                    value4 = s0Var.getValue();
                } while (!s0Var.k(value4, w.a((w) value4, i.c, false, false, false, null, 30)));
                return;
            }
            boolean z3 = zVar instanceof com.quizlet.login.common.interactors.data.u;
            d0 d0Var = this.i;
            if (z3) {
                com.quizlet.login.common.interactors.data.u uVar = (com.quizlet.login.common.interactors.data.u) zVar;
                d0Var.h(new com.quizlet.login.login.data.q(uVar.a, uVar.b));
                return;
            }
            if (Intrinsics.b(zVar, x.a)) {
                d0Var.h(com.quizlet.login.login.data.u.a);
                return;
            }
            if (Intrinsics.b(zVar, com.quizlet.login.common.interactors.data.w.a)) {
                d0Var.h(com.quizlet.login.login.data.n.a);
                return;
            }
            if (zVar instanceof y) {
                String str = ((y) zVar).a;
                do {
                    value3 = s0Var.getValue();
                } while (!s0Var.k(value3, w.a((w) value3, new j(str), false, false, false, null, 28)));
                return;
            }
            if (Intrinsics.b(zVar, o.a)) {
                do {
                    value2 = s0Var.getValue();
                } while (!s0Var.k(value2, w.a((w) value2, com.quizlet.login.authentication.d.c, false, false, false, null, 30)));
                return;
            }
            if (Intrinsics.b(zVar, t.a)) {
                d0Var.h(com.quizlet.login.login.data.o.a);
                return;
            }
            if (Intrinsics.b(zVar, s.a)) {
                d0Var.h(com.quizlet.login.login.data.m.a);
                return;
            }
            if (zVar instanceof k) {
                String str2 = ((k) zVar).a;
                do {
                    value = s0Var.getValue();
                } while (!s0Var.k(value, w.a((w) value, com.quizlet.login.authentication.a.c, false, false, false, str2, 14)));
                return;
            } else {
                if (zVar instanceof r) {
                    d0Var.h(new p(((r) zVar).a));
                    return;
                }
                if (!(zVar instanceof v) && !Intrinsics.b(zVar, com.quizlet.login.common.interactors.data.p.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                timber.log.c.a.p(new kotlin.n(f.class.getName() + " " + zVar));
                return;
            }
        }
        com.quizlet.login.authentication.data.b bVar = ((l) zVar).a;
        if (bVar.a == null) {
            D(true);
            return;
        }
        while (true) {
            Object value6 = s0Var.getValue();
            boolean z4 = z;
            if (s0Var.k(value6, w.a((w) value6, new com.quizlet.login.authentication.b(bVar.a), z4, false, false, null, 28))) {
                return;
            } else {
                z = z4;
            }
        }
    }

    public final void D(boolean z) {
        s0 s0Var;
        Object value;
        if (z) {
            do {
                s0Var = this.h;
                value = s0Var.getValue();
            } while (!s0Var.k(value, w.a((w) value, com.quizlet.login.authentication.h.c, false, false, false, null, 30)));
        }
    }

    public final void E(com.quizlet.login.login.data.k event) {
        Object value;
        Object value2;
        Object value3;
        Intrinsics.checkNotNullParameter(event, "event");
        boolean zB = Intrinsics.b(event, com.quizlet.login.login.data.a.a);
        d0 d0Var = this.i;
        if (zB) {
            d0Var.h(com.quizlet.login.login.data.l.a);
            return;
        }
        boolean z = event instanceof com.quizlet.login.login.data.e;
        h hVar = this.b;
        if (z) {
            com.quizlet.login.login.data.e eVar = (com.quizlet.login.login.data.e) event;
            String str = eVar.a;
            if (StringsKt.O(str)) {
                return;
            }
            String str2 = eVar.b;
            if (StringsKt.O(str2)) {
                return;
            }
            EventLoggerExt.c(hVar.a, new com.quizlet.quizletandroid.ui.login.z(0));
            E.A(p0.j(this), null, null, new b(this, str, str2, null), 3);
            return;
        }
        if (Intrinsics.b(event, com.quizlet.login.login.data.f.a)) {
            d0Var.h(com.quizlet.login.login.data.r.a);
            return;
        }
        boolean zB2 = Intrinsics.b(event, com.quizlet.login.login.data.c.a);
        com.google.android.gms.internal.appset.e eVar2 = this.c;
        if (zB2) {
            d0Var.h(com.quizlet.login.login.data.s.a);
            EventLoggerExt.c(hVar.a, new com.quizlet.quizletandroid.ui.login.z(5));
            eVar2.r("facebook", false);
            return;
        }
        if (event instanceof g) {
            E.A(p0.j(this), null, null, new d(this, ((g) event).a, null), 3);
            return;
        }
        boolean z2 = event instanceof com.quizlet.login.login.data.h;
        s0 s0Var = this.h;
        if (z2) {
            timber.log.c.a.p(((com.quizlet.login.login.data.h) event).a);
            do {
                value3 = s0Var.getValue();
            } while (!s0Var.k(value3, w.a((w) value3, com.quizlet.login.authentication.e.c, false, false, false, null, 30)));
            return;
        }
        if (Intrinsics.b(event, com.quizlet.login.login.data.d.a)) {
            d0Var.h(com.quizlet.login.login.data.t.a);
            EventLoggerExt.c(hVar.a, new com.quizlet.quizletandroid.ui.login.z(2));
            eVar2.r(OTVendorListMode.GOOGLE, false);
            return;
        }
        if (event instanceof com.quizlet.login.login.data.i) {
            E.A(p0.j(this), null, null, new c(this, ((com.quizlet.login.login.data.i) event).a, null), 3);
        } else {
            if (event instanceof com.quizlet.login.login.data.j) {
                timber.log.c.a.p(((com.quizlet.login.login.data.j) event).a);
                do {
                    value2 = s0Var.getValue();
                } while (!s0Var.k(value2, w.a((w) value2, com.quizlet.login.authentication.f.c, false, false, false, null, 30)));
                return;
            }
            if (!Intrinsics.b(event, com.quizlet.login.login.data.b.a)) {
                throw new NoWhenBranchMatchedException();
            }
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, w.a((w) value, null, false, false, false, null, 30)));
        }
    }
}
