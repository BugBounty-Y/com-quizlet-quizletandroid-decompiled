package com.quizlet.features.questionnaire.navigation;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.paging.J0;
import com.amazon.device.ads.DtbDeviceData;
import java.util.ArrayDeque;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class m extends w0 implements b {
    public final m0 b;
    public final com.onetrust.otpublishers.headless.Internal.Helper.h c;
    public final s0 d;
    public final s0 e;
    public final ArrayDeque f;

    /* JADX WARN: Type inference failed for: r2v6, types: [kotlinx.coroutines.flow.i, kotlinx.coroutines.flow.internal.a] */
    public m(m0 savedStateHandle, com.onetrust.otpublishers.headless.Internal.Helper.h repository, AbstractC5040y dispatcher, com.quizlet.usecase.a questionnaireShimObserver) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(questionnaireShimObserver, "questionnaireShimObserver");
        this.b = savedStateHandle;
        this.c = repository;
        this.d = e0.c(h.a);
        this.e = e0.c(Boolean.TRUE);
        this.f = new ArrayDeque();
        e0.w(new J0(questionnaireShimObserver.a, new j(this, null), 5), p0.j(this));
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.features.questionnaire.navigation.m r4, java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4.getClass()
            boolean r0 = r6 instanceof com.quizlet.features.questionnaire.navigation.k
            if (r0 == 0) goto L16
            r0 = r6
            com.quizlet.features.questionnaire.navigation.k r0 = (com.quizlet.features.questionnaire.navigation.k) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            com.quizlet.features.questionnaire.navigation.k r0 = new com.quizlet.features.questionnaire.navigation.k
            r0.<init>(r4, r6)
        L1b:
            java.lang.Object r6 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L36
            if (r2 != r3) goto L2e
            java.lang.String r5 = r0.k
            com.quizlet.features.questionnaire.navigation.m r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L46
        L2e:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.k = r5
            r0.n = r3
            java.lang.Object r6 = r4.C(r0)
            if (r6 != r1) goto L46
            return r1
        L46:
            r4.B(r5)
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questionnaire.navigation.m.A(com.quizlet.features.questionnaire.navigation.m, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void B(String str) {
        QuestionnaireModel questionnaireModel = (QuestionnaireModel) this.b.a(DtbDeviceData.DEVICE_DATA_MODEL_KEY);
        StepModel stepModel = questionnaireModel != null ? (StepModel) questionnaireModel.b.get(str) : null;
        s0 s0Var = this.d;
        if (str == null || stepModel == null) {
            g gVar = g.a;
            s0Var.getClass();
            s0Var.m(null, gVar);
            return;
        }
        ArrayDeque arrayDeque = this.f;
        arrayDeque.addLast(str);
        f fVar = new f(stepModel);
        s0Var.getClass();
        s0Var.m(null, fVar);
        Boolean boolValueOf = Boolean.valueOf(arrayDeque.size() <= 1);
        s0 s0Var2 = this.e;
        s0Var2.getClass();
        s0Var2.m(null, boolValueOf);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object C(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.features.questionnaire.navigation.l
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.features.questionnaire.navigation.l r0 = (com.quizlet.features.questionnaire.navigation.l) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.questionnaire.navigation.l r0 = new com.quizlet.features.questionnaire.navigation.l
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlin.r r5 = (kotlin.r) r5
            r5.getClass()
            goto L54
        L2c:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlinx.coroutines.flow.s0 r5 = r4.d
            java.lang.Object r5 = r5.getValue()
            boolean r2 = r5 instanceof com.quizlet.features.questionnaire.navigation.f
            if (r2 != 0) goto L42
            r5 = 0
        L42:
            com.quizlet.features.questionnaire.navigation.f r5 = (com.quizlet.features.questionnaire.navigation.f) r5
            if (r5 == 0) goto L57
            r0.l = r3
            com.onetrust.otpublishers.headless.Internal.Helper.h r5 = r4.c
            r5.getClass()
            kotlin.p r5 = kotlin.r.b
            kotlin.Unit r5 = kotlin.Unit.a
            if (r5 != r1) goto L54
            return r1
        L54:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L57:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.questionnaire.navigation.m.C(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
