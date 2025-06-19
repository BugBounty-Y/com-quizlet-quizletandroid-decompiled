package com.quizlet.quizletandroid.ui.globalnav.viewmodel;

import androidx.compose.material3.internal.H;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.paging.J0;
import com.quizlet.quizletandroid.interactor.t;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Create;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$FreeTrial;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Home;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Upgrade;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$YourLibrary;
import com.quizlet.quizletandroid.ui.globalnav.data.k;
import com.quizlet.quizletandroid.ui.globalnav.data.l;
import com.quizlet.quizletandroid.ui.globalnav.data.m;
import com.quizlet.quizletandroid.ui.globalnav.data.n;
import com.quizlet.quizletandroid.ui.globalnav.data.o;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.h0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class e extends w0 implements h {
    public static final List l = B.j(GlobalNavSuiteItem$Home.INSTANCE, GlobalNavSuiteItem$Create.INSTANCE, new GlobalNavSuiteItem$YourLibrary(null));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e b;
    public final com.quizlet.quizletandroid.ui.globalnav.logging.a c;
    public final com.quizlet.data.repository.user.a d;
    public final Z e;
    public final s0 f;
    public final Z g;
    public final d0 h;
    public final s0 i;
    public final d0 j;
    public boolean k;

    public e(t loggedInUserInteractor, com.quizlet.data.repository.folderwithcreatorinclass.e compatibilityCheckerManager, com.quizlet.quizletandroid.ui.globalnav.logging.a globalNavigationEventLogger, com.quizlet.data.repository.user.a bts2025FeedFeature) {
        Intrinsics.checkNotNullParameter(loggedInUserInteractor, "loggedInUserInteractor");
        Intrinsics.checkNotNullParameter(compatibilityCheckerManager, "compatibilityCheckerManager");
        Intrinsics.checkNotNullParameter(globalNavigationEventLogger, "globalNavigationEventLogger");
        Intrinsics.checkNotNullParameter(bts2025FeedFeature, "bts2025FeedFeature");
        this.b = compatibilityCheckerManager;
        this.c = globalNavigationEventLogger;
        this.d = bts2025FeedFeature;
        this.e = e0.x(new H(10, loggedInUserInteractor.a(true), this), p0.j(this), h0.a(3), kotlinx.collections.immutable.implementations.immutableList.g.c);
        s0 s0VarC = e0.c(null);
        this.f = s0VarC;
        this.g = e0.x(new J0(new c(this, null), s0VarC), p0.j(this), h0.a(3), null);
        this.h = e0.b(0, 1, null, 5);
        this.i = e0.c(Boolean.FALSE);
        this.j = e0.b(0, 1, null, 5);
        E.A(p0.j(this), null, null, new a(this, null), 3);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.quizletandroid.ui.globalnav.viewmodel.e r5, kotlin.coroutines.jvm.internal.c r6) throws java.lang.Throwable {
        /*
            r5.getClass()
            boolean r0 = r6 instanceof com.quizlet.quizletandroid.ui.globalnav.viewmodel.b
            if (r0 == 0) goto L16
            r0 = r6
            com.quizlet.quizletandroid.ui.globalnav.viewmodel.b r0 = (com.quizlet.quizletandroid.ui.globalnav.viewmodel.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.quizletandroid.ui.globalnav.viewmodel.b r0 = new com.quizlet.quizletandroid.ui.globalnav.viewmodel.b
            r0.<init>(r5, r6)
        L1b:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            com.quizlet.quizletandroid.ui.globalnav.viewmodel.e r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L52
        L2c:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.m = r3
            com.quizlet.data.repository.folderwithcreatorinclass.e r6 = r5.b
            r6.getClass()
            com.quizlet.features.infra.compatibility.d r2 = new com.quizlet.features.infra.compatibility.d
            r3 = 0
            r4 = 0
            r2.<init>(r6, r4, r3)
            java.lang.Object r6 = r6.e
            kotlinx.coroutines.y r6 = (kotlinx.coroutines.AbstractC5040y) r6
            java.lang.Object r6 = kotlinx.coroutines.E.J(r6, r2, r0)
            if (r6 != r1) goto L52
            return r1
        L52:
            com.quizlet.features.infra.compatibility.a r6 = (com.quizlet.features.infra.compatibility.a) r6
            if (r6 == 0) goto L74
            kotlin.jvm.functions.Function0 r0 = r6.c
            if (r0 != 0) goto L65
            com.quizlet.login.magiclink.ui.e r0 = new com.quizlet.login.magiclink.ui.e
            r1 = 13
            r0.<init>(r5, r1)
            com.quizlet.features.infra.compatibility.a r6 = com.quizlet.features.infra.compatibility.a.a(r6, r0)
        L65:
            kotlinx.coroutines.flow.s0 r5 = r5.f
        L67:
            java.lang.Object r0 = r5.getValue()
            r1 = r0
            com.quizlet.features.infra.compatibility.a r1 = (com.quizlet.features.infra.compatibility.a) r1
            boolean r0 = r5.k(r0, r6)
            if (r0 == 0) goto L67
        L74:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.globalnav.viewmodel.e.A(com.quizlet.quizletandroid.ui.globalnav.viewmodel.e, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void B(o event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (event instanceof n) {
            this.h.h(((n) event).a);
            return;
        }
        if (!(event instanceof m)) {
            if (!Intrinsics.b(event, l.a)) {
                throw new NoWhenBranchMatchedException();
            }
            if (this.k) {
                return;
            }
            this.k = true;
            this.j.h(Unit.a);
            return;
        }
        k kVar = ((m) event).a;
        boolean zB = Intrinsics.b(kVar, GlobalNavSuiteItem$Create.INSTANCE);
        com.quizlet.quizletandroid.ui.globalnav.logging.a aVar = this.c;
        if (zB) {
            aVar.getClass();
            aVar.a("clicked_create", "Homepage", "bottom_nav");
            return;
        }
        if ((kVar instanceof GlobalNavSuiteItem$FreeTrial) || (kVar instanceof GlobalNavSuiteItem$Upgrade)) {
            aVar.getClass();
            aVar.a("clicked_upgrade", "Homepage", "bottom_nav");
        } else if (Intrinsics.b(kVar, GlobalNavSuiteItem$Home.INSTANCE)) {
            aVar.getClass();
            aVar.a("clicked_home", "Homepage", "bottom_nav");
        } else {
            if (!(kVar instanceof GlobalNavSuiteItem$YourLibrary)) {
                throw new NoWhenBranchMatchedException();
            }
            aVar.getClass();
            aVar.a("clicked_your_library", "Homepage", "bottom_nav");
        }
    }
}
