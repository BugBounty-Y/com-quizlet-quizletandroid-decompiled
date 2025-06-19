package com.quizlet.features.infra.folder.menu.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public int k;
    public final /* synthetic */ m l;
    public final /* synthetic */ String m;
    public final /* synthetic */ long n;
    public final /* synthetic */ long o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(m mVar, String str, long j, long j2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = mVar;
        this.m = str;
        this.n = j;
        this.o = j2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0078  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.k
            r2 = 2
            r3 = 1
            com.quizlet.features.infra.folder.menu.viewmodel.m r4 = r12.l
            if (r1 == 0) goto L26
            if (r1 == r3) goto L1d
            if (r1 != r2) goto L15
            java.lang.Object r0 = r12.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r11 = r12
            goto L64
        L15:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L1d:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            kotlin.r r13 = (kotlin.r) r13
            java.lang.Object r13 = r13.a
            r11 = r12
            goto L3b
        L26:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            androidx.compose.material.ripple.r r5 = r4.a
            r12.k = r3
            long r7 = r12.n
            long r9 = r12.o
            java.lang.String r6 = r12.m
            r11 = r12
            java.lang.Object r13 = r5.d(r6, r7, r9, r11)
            if (r13 != r0) goto L3b
            goto L62
        L3b:
            kotlin.p r1 = kotlin.r.b
            boolean r1 = r13 instanceof kotlin.q
            if (r1 != 0) goto L72
            r1 = r13
            com.quizlet.data.model.d0 r1 = (com.quizlet.data.model.AbstractC4119d0) r1
            com.quizlet.data.interactor.folderstudymaterial.d r3 = new com.quizlet.data.interactor.folderstudymaterial.d
            long r5 = r1.a()
            java.lang.String r1 = r4.m
            r7 = 0
            if (r1 == 0) goto L6c
            com.quizlet.generated.enums.y1 r8 = r4.l
            if (r8 == 0) goto L66
            r3.<init>(r5, r1, r8)
            r11.j = r13
            r11.k = r2
            java.lang.String r1 = r11.m
            java.lang.Object r1 = com.quizlet.features.infra.folder.menu.viewmodel.m.a(r4, r1, r3, r12)
            if (r1 != r0) goto L63
        L62:
            return r0
        L63:
            r0 = r13
        L64:
            r13 = r0
            goto L72
        L66:
            java.lang.String r13 = "studyMaterialType"
            kotlin.jvm.internal.Intrinsics.m(r13)
            throw r7
        L6c:
            java.lang.String r13 = "studyMaterialId"
            kotlin.jvm.internal.Intrinsics.m(r13)
            throw r7
        L72:
            java.lang.Throwable r13 = kotlin.r.a(r13)
            if (r13 == 0) goto L82
            kotlinx.coroutines.flow.d0 r0 = r4.h
            com.quizlet.features.infra.folder.menu.data.n r1 = new com.quizlet.features.infra.folder.menu.data.n
            r1.<init>(r13)
            r0.h(r1)
        L82:
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.menu.viewmodel.g.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
