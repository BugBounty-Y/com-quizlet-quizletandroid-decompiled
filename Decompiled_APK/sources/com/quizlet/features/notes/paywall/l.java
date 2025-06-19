package com.quizlet.features.notes.paywall;

import androidx.lifecycle.Y;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.ScanNotesPaywallEventLog;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class l extends w0 implements i {
    public final com.google.mlkit.vision.documentscanner.internal.c b;
    public final androidx.work.impl.model.e c;
    public final Y d;
    public final s0 e;
    public final s0 f;

    public l(com.google.mlkit.vision.documentscanner.internal.c logger, androidx.work.impl.model.e userHasFreeTrialUseCase) {
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(userHasFreeTrialUseCase, "userHasFreeTrialUseCase");
        this.b = logger;
        this.c = userHasFreeTrialUseCase;
        this.d = new Y();
        s0 s0VarC = e0.c(g.a);
        this.e = s0VarC;
        this.f = s0VarC;
        ((EventLogger) logger.b).l(new ScanNotesPaywallEventLog("notes_meter_exceeded", "notes_to_value_paywall_impression"));
        E.A(p0.j(this), null, null, new j(this, null), 3);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.features.notes.paywall.l r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4.getClass()
            boolean r0 = r5 instanceof com.quizlet.features.notes.paywall.k
            if (r0 == 0) goto L16
            r0 = r5
            com.quizlet.features.notes.paywall.k r0 = (com.quizlet.features.notes.paywall.k) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.l = r1
            goto L1b
        L16:
            com.quizlet.features.notes.paywall.k r0 = new com.quizlet.features.notes.paywall.k
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
            com.quizlet.features.notes.paywall.f r5 = new com.quizlet.features.notes.paywall.f
            r5.<init>(r4)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.notes.paywall.l.A(com.quizlet.features.notes.paywall.l, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
