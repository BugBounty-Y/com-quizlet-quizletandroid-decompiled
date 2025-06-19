package com.quizlet.quizletandroid.ui.learnpaywall;

import com.quizlet.studiablemodels.StudiableMeteringData;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ k j;
    public final /* synthetic */ long k;
    public final /* synthetic */ String l;
    public final /* synthetic */ StudiableMeteringData m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(k kVar, long j, String str, StudiableMeteringData studiableMeteringData, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = kVar;
        this.k = j;
        this.l = str;
        this.m = studiableMeteringData;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.j, this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x003d  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x005a  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0068  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            androidx.glance.appwidget.protobuf.Z.e(r10)
            com.quizlet.quizletandroid.ui.learnpaywall.k r10 = r9.j
            com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger r0 = r10.b
            r0.getClass()
            java.lang.String r4 = r9.l
            java.lang.String r1 = "studySessionId"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r1)
            com.quizlet.studiablemodels.StudiableMeteringData r3 = r9.m
            java.lang.String r1 = "meteringData"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r1)
            com.quizlet.shared.enums.h r1 = r3.a
            int r1 = r1.ordinal()
            r6 = 0
            r7 = 2
            r8 = 1
            if (r1 == r8) goto L2d
            if (r1 == r7) goto L29
            r5 = r6
            goto L30
        L29:
            java.lang.String r1 = "test_remaining_attempts_paywall_impression"
        L2b:
            r5 = r1
            goto L30
        L2d:
            java.lang.String r1 = "learn_remaining_rounds_paywall_impression"
            goto L2b
        L30:
            long r1 = r9.k
            r0.b(r1, r3, r4, r5)
            com.quizlet.shared.enums.h r0 = r3.a
            int r0 = r0.ordinal()
            if (r0 == 0) goto L57
            if (r0 == r8) goto L4f
            if (r0 != r7) goto L49
            com.quizlet.quizletandroid.ui.learnpaywall.c r0 = new com.quizlet.quizletandroid.ui.learnpaywall.c
            com.quizlet.quizletandroid.ui.learnpaywall.b r1 = com.quizlet.quizletandroid.ui.learnpaywall.b.d
            r0.<init>(r1)
            goto L58
        L49:
            kotlin.NoWhenBranchMatchedException r10 = new kotlin.NoWhenBranchMatchedException
            r10.<init>()
            throw r10
        L4f:
            com.quizlet.quizletandroid.ui.learnpaywall.c r0 = new com.quizlet.quizletandroid.ui.learnpaywall.c
            com.quizlet.quizletandroid.ui.learnpaywall.b r1 = com.quizlet.quizletandroid.ui.learnpaywall.b.c
            r0.<init>(r1)
            goto L58
        L57:
            r0 = r6
        L58:
            if (r0 == 0) goto L68
            androidx.lifecycle.viewmodel.internal.a r1 = androidx.lifecycle.p0.j(r10)
            com.quizlet.quizletandroid.ui.learnpaywall.j r2 = new com.quizlet.quizletandroid.ui.learnpaywall.j
            r2.<init>(r10, r0, r6)
            r10 = 3
            kotlinx.coroutines.E.A(r1, r6, r6, r2, r10)
            goto L6b
        L68:
            r10.B()
        L6b:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.learnpaywall.h.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
