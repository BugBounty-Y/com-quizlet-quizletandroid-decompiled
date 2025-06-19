package com.quizlet.quizletandroid.ui.startpage.nav2;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4699h implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ OldHomeFragment b;

    public /* synthetic */ C4699h(OldHomeFragment oldHomeFragment, int i) {
        this.a = i;
        this.b = oldHomeFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                OldHomeFragment oldHomeFragment = this.b;
                com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L l = oldHomeFragment.Z;
                Y y = oldHomeFragment.t;
                if (y != null) {
                    return new com.quizlet.quizletandroid.ui.startpage.nav2.adapters.k(l, y, y);
                }
                Intrinsics.m("viewModel");
                throw null;
            case 1:
                OldHomeFragment oldHomeFragment2 = this.b;
                com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L l2 = oldHomeFragment2.Z;
                Y y2 = oldHomeFragment2.t;
                if (y2 != null) {
                    return new com.quizlet.quizletandroid.ui.startpage.nav2.adapters.l(l2, y2, y2);
                }
                Intrinsics.m("viewModel");
                throw null;
            case 2:
                OldHomeFragment oldHomeFragment3 = this.b;
                com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L l3 = oldHomeFragment3.Z;
                Y y3 = oldHomeFragment3.t;
                if (y3 != null) {
                    return new com.quizlet.quizletandroid.ui.startpage.nav2.adapters.h(l3, y3, y3);
                }
                Intrinsics.m("viewModel");
                throw null;
            case 3:
                OldHomeFragment oldHomeFragment4 = this.b;
                Y y4 = oldHomeFragment4.t;
                if (y4 == null) {
                    Intrinsics.m("viewModel");
                    throw null;
                }
                com.quizlet.infra.legacysyncengine.managers.d dVar = oldHomeFragment4.k;
                if (dVar != null) {
                    return new com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o(y4, y4, y4, dVar);
                }
                Intrinsics.m("loggedInUserManager");
                throw null;
            case 4:
                OldHomeFragment oldHomeFragment5 = this.b;
                Y y5 = oldHomeFragment5.t;
                if (y5 == null) {
                    Intrinsics.m("viewModel");
                    throw null;
                }
                com.quizlet.infra.legacysyncengine.managers.d dVar2 = oldHomeFragment5.k;
                if (dVar2 != null) {
                    return new com.quizlet.quizletandroid.ui.startpage.nav2.adapters.o(y5, y5, y5, dVar2);
                }
                Intrinsics.m("loggedInUserManager");
                throw null;
            case 5:
                return new com.quizlet.quizletandroid.ui.startpage.nav2.adapters.p(this.b.Z);
            case 6:
                return new com.quizlet.quizletandroid.ui.startpage.nav2.adapters.f(this.b.Z);
            case 7:
                return new com.quizlet.quizletandroid.ui.startpage.nav2.adapters.p(this.b.Z);
            case 8:
                OldHomeFragment oldHomeFragment6 = this.b;
                return new com.quizlet.quizletandroid.ui.startpage.nav2.adapters.e(oldHomeFragment6.Z, (com.quizlet.features.achievements.home.a) oldHomeFragment6.x.getValue());
            case 9:
                OldHomeFragment oldHomeFragment7 = this.b;
                if (oldHomeFragment7.p == null) {
                    Intrinsics.m("homePrivacyPolicySectionAdapterFactory");
                    throw null;
                }
                com.quizlet.quizletandroid.ui.globalnav.composable.n onClick = new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, (com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L) oldHomeFragment7.v.getValue(), com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L.class, "onPrivacyPolicyLinkClick", "onPrivacyPolicyLinkClick()V", 0, 16);
                Intrinsics.checkNotNullParameter(onClick, "onClick");
                return new com.quizlet.quizletandroid.ui.startpage.nav2.adapters.m(onClick);
            case 10:
                OldHomeFragment oldHomeFragment8 = this.b;
                com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L l4 = oldHomeFragment8.Z;
                Y y6 = oldHomeFragment8.t;
                if (y6 != null) {
                    return new com.quizlet.quizletandroid.ui.startpage.nav2.adapters.j(l4, y6);
                }
                Intrinsics.m("viewModel");
                throw null;
            case 11:
                OldHomeFragment oldHomeFragment9 = this.b;
                Y y7 = oldHomeFragment9.t;
                if (y7 == null) {
                    Intrinsics.m("viewModel");
                    throw null;
                }
                com.quizlet.infra.legacysyncengine.managers.d dVar3 = oldHomeFragment9.k;
                if (dVar3 != null) {
                    return new com.quizlet.quizletandroid.ui.startpage.nav2.adapters.q(y7, y7, y7, dVar3);
                }
                Intrinsics.m("loggedInUserManager");
                throw null;
            default:
                if (this.b.s != null) {
                    return Unit.a;
                }
                Intrinsics.m("devToolsManager");
                throw null;
        }
    }
}
