package com.quizlet.quizletandroid.ui.learnpaywall;

import androidx.compose.ui.platform.C0958o;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger;
import com.quizlet.studiablemodels.StudiableMeteringData;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class k extends w0 implements com.quizlet.upgrade.paywall.viewmodel.a {
    public final StudyModeMeteringEventLogger b;
    public final androidx.work.impl.model.e c;
    public final d0 d;
    public final s0 e;
    public final d0 f;
    public b g;
    public Long h;
    public String i;
    public StudiableMeteringData j;
    public boolean k;

    public k(com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, StudyModeMeteringEventLogger meteringEventLogger, androidx.work.impl.model.e userHasFreeTrialUseCase) {
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(meteringEventLogger, "meteringEventLogger");
        Intrinsics.checkNotNullParameter(userHasFreeTrialUseCase, "userHasFreeTrialUseCase");
        this.b = meteringEventLogger;
        this.c = userHasFreeTrialUseCase;
        this.d = e0.b(0, 0, null, 7);
        this.e = e0.c(com.quizlet.upgrade.paywall.data.e.a);
        this.f = e0.b(0, 0, null, 7);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.quizletandroid.ui.learnpaywall.k r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4.getClass()
            boolean r0 = r5 instanceof com.quizlet.quizletandroid.ui.learnpaywall.d
            if (r0 == 0) goto L16
            r0 = r5
            com.quizlet.quizletandroid.ui.learnpaywall.d r0 = (com.quizlet.quizletandroid.ui.learnpaywall.d) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.l = r1
            goto L1b
        L16:
            com.quizlet.quizletandroid.ui.learnpaywall.d r0 = new com.quizlet.quizletandroid.ui.learnpaywall.d
            r0.<init>(r4, r5)
        L1b:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L41
        L2a:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L32:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.l = r3
            r5 = 0
            androidx.work.impl.model.e r4 = r4.c
            java.lang.Object r5 = r4.s(r5, r0)
            if (r5 != r1) goto L41
            return r1
        L41:
            com.quizlet.data.model.u2 r5 = (com.quizlet.data.model.u2) r5
            int r4 = r5.a
            com.quizlet.upgrade.paywall.data.d r5 = new com.quizlet.upgrade.paywall.data.d
            r5.<init>(r4)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.learnpaywall.k.A(com.quizlet.quizletandroid.ui.learnpaywall.k, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void B() {
        C0958o c0958o = new C0958o(3, this.b, StudyModeMeteringEventLogger.class, "logPaywallDismissed", "logPaywallDismissed(JLjava/lang/String;Lcom/quizlet/studiablemodels/StudiableMeteringData;)V", 0, 2);
        Long l = this.h;
        String str = this.i;
        StudiableMeteringData studiableMeteringData = this.j;
        if (l != null && str != null && studiableMeteringData != null) {
            c0958o.invoke(l, str, studiableMeteringData);
        }
        E.A(p0.j(this), null, null, new e(this, null), 3);
    }

    public final void C(long j, String studySessionId, StudiableMeteringData meteringData, boolean z) {
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        Intrinsics.checkNotNullParameter(meteringData, "meteringData");
        this.h = Long.valueOf(j);
        this.i = studySessionId;
        this.j = meteringData;
        this.k = z;
        E.A(p0.j(this), null, null, new h(this, j, studySessionId, meteringData, null), 3);
    }
}
