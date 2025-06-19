package com.quizlet.learn.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.learn.viewmodel.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4554a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public C4556c j;
    public int k;
    public int l;
    public int m;
    public final /* synthetic */ C4556c n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4554a(C4556c c4556c, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = c4556c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4554a(this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4554a) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0073  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.m
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L26
            if (r1 == r3) goto L1e
            if (r1 != r2) goto L16
            int r0 = r9.l
            int r1 = r9.k
            com.quizlet.learn.viewmodel.c r2 = r9.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L6b
        L16:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L1e:
            int r1 = r9.k
            com.quizlet.learn.viewmodel.c r4 = r9.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L4d
        L26:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            com.quizlet.learn.viewmodel.c r10 = r9.n
            com.quizlet.studiablemodels.StudiableMeteringData r1 = r10.f
            if (r1 == 0) goto Lc7
            java.lang.Integer r1 = r1.e
            if (r1 == 0) goto Lc7
            int r1 = r1.intValue()
            androidx.work.impl.model.c r4 = r10.c
            io.reactivex.rxjava3.internal.operators.single.g r4 = r4.y()
            r9.j = r10
            r9.k = r1
            r9.m = r3
            java.lang.Object r4 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r4, r9)
            if (r4 != r0) goto L4a
            goto L68
        L4a:
            r8 = r4
            r4 = r10
            r10 = r8
        L4d:
            java.lang.String r5 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r10, r5)
            java.lang.Number r10 = (java.lang.Number) r10
            int r10 = r10.intValue()
            r9.j = r4
            r9.k = r1
            r9.l = r10
            r9.m = r2
            r5 = 100
            java.lang.Object r2 = kotlinx.coroutines.E.n(r5, r9)
            if (r2 != r0) goto L69
        L68:
            return r0
        L69:
            r0 = r10
            r2 = r4
        L6b:
            r2.getClass()
            if (r0 != r3) goto L73
            com.quizlet.ui.states.a r10 = com.quizlet.ui.states.a.d
            goto L75
        L73:
            com.quizlet.ui.states.a r10 = com.quizlet.ui.states.a.c
        L75:
            com.quizlet.learn.ui.g r0 = new com.quizlet.learn.ui.g
            java.lang.Integer r4 = java.lang.Integer.valueOf(r1)
            java.lang.Object[] r4 = new java.lang.Object[]{r4}
            java.lang.String r5 = "args"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r5)
            com.quizlet.qutils.string.d r6 = new com.quizlet.qutils.string.d
            java.util.List r4 = kotlin.collections.C4933y.P(r4)
            r7 = 2131886109(0x7f12001d, float:1.9406788E38)
            r6.<init>(r7, r1, r4)
            r1 = 0
            java.lang.Object[] r1 = new java.lang.Object[r1]
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r5)
            com.quizlet.qutils.string.f r4 = new com.quizlet.qutils.string.f
            java.util.List r1 = kotlin.collections.C4933y.P(r1)
            r5 = 2132018456(0x7f140518, float:1.967522E38)
            r4.<init>(r5, r1)
            r0.<init>(r10, r6, r4)
        La5:
            kotlinx.coroutines.flow.s0 r10 = r2.h
            java.lang.Object r1 = r10.getValue()
            r4 = r1
            com.quizlet.learn.data.A r4 = (com.quizlet.learn.data.A) r4
            java.lang.String r5 = "null cannot be cast to non-null type com.quizlet.learn.data.LearningEndingViewState.Content"
            kotlin.jvm.internal.Intrinsics.e(r4, r5)
            com.quizlet.learn.data.y r4 = (com.quizlet.learn.data.y) r4
            com.quizlet.learn.data.e r4 = r4.a
            java.lang.String r5 = "endState"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r5)
            com.quizlet.learn.data.y r5 = new com.quizlet.learn.data.y
            r5.<init>(r4, r3, r0)
            boolean r10 = r10.k(r1, r5)
            if (r10 == 0) goto La5
        Lc7:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.learn.viewmodel.C4554a.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
