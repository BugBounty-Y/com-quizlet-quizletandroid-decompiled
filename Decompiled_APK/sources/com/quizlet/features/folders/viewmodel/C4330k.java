package com.quizlet.features.folders.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.folders.viewmodel.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4330k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public N k;
    public com.quizlet.ui.models.content.listitem.o l;
    public int m;
    public final /* synthetic */ N n;
    public final /* synthetic */ com.quizlet.ui.models.content.listitem.o o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4330k(N n, com.quizlet.ui.models.content.listitem.o oVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = n;
        this.o = oVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4330k(this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4330k) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:28:0x00c7, code lost:
    
        if (r3.emit(r5, r17) == r1) goto L29;
     */
    /* JADX WARN: Removed duplicated region for block: B:24:0x00a5  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r18) {
        /*
            r17 = this;
            r0 = r17
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            com.quizlet.features.folders.viewmodel.N r3 = r0.n
            r4 = 3
            r5 = 2
            r6 = 1
            com.quizlet.ui.models.content.listitem.o r7 = r0.o
            if (r2 == 0) goto L36
            if (r2 == r6) goto L2c
            if (r2 == r5) goto L22
            if (r2 != r4) goto L1a
            androidx.glance.appwidget.protobuf.Z.e(r18)
            goto Lca
        L1a:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L22:
            com.quizlet.ui.models.content.listitem.o r7 = r0.l
            com.quizlet.features.folders.viewmodel.N r2 = r0.k
            java.lang.Object r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r18)
            goto L6e
        L2c:
            androidx.glance.appwidget.protobuf.Z.e(r18)
            r2 = r18
            kotlin.r r2 = (kotlin.r) r2
            java.lang.Object r2 = r2.a
            goto L54
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r18)
            com.quizlet.data.interactor.folderstudymaterial.d r2 = new com.quizlet.data.interactor.folderstudymaterial.d
            long r8 = r3.s
            java.lang.String r10 = r7.d()
            com.quizlet.generated.enums.y1 r11 = r7.b()
            r2.<init>(r8, r10, r11)
            r0.m = r6
            com.onetrust.otpublishers.headless.UI.fragment.q r6 = r3.f
            java.lang.Object r2 = r6.q(r2, r0)
            if (r2 != r1) goto L54
            goto Lc9
        L54:
            kotlin.p r6 = kotlin.r.b
            boolean r6 = r2 instanceof kotlin.q
            if (r6 != 0) goto L9f
            r6 = r2
            com.quizlet.data.interactor.folderstudymaterial.h r6 = (com.quizlet.data.interactor.folderstudymaterial.h) r6
            r0.j = r2
            r0.k = r3
            r0.l = r7
            r0.m = r5
            java.lang.Object r5 = com.quizlet.features.folders.viewmodel.N.C(r3, r0)
            if (r5 != r1) goto L6c
            goto Lc9
        L6c:
            r5 = r2
            r2 = r3
        L6e:
            com.quizlet.features.folders.logging.e r6 = r2.h
            long r9 = r2.s
            java.lang.String r11 = r7.d()
            com.quizlet.generated.enums.y1 r12 = r7.b()
            r6.getClass()
            java.lang.String r2 = "studyMaterialId"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r11, r2)
            java.lang.String r2 = "studyMaterialType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r12, r2)
            com.quizlet.features.folders.logging.f r8 = new com.quizlet.features.folders.logging.f
            r14 = 0
            r16 = 248(0xf8, float:3.48E-43)
            r13 = 0
            r15 = 0
            r8.<init>(r9, r11, r12, r13, r14, r15, r16)
            com.quizlet.features.folders.logging.b r2 = new com.quizlet.features.folders.logging.b
            r7 = 0
            r2.<init>(r8, r7)
            com.quizlet.eventlogger.EventLogger r6 = r6.a
            java.lang.String r7 = "heterogeneous_folders_recommendation_added"
            com.quizlet.eventlogger.EventLoggerExt.a(r6, r7, r2)
            r2 = r5
        L9f:
            java.lang.Throwable r5 = kotlin.r.a(r2)
            if (r5 == 0) goto Lca
            boolean r5 = r5 instanceof com.quizlet.data.connectivity.NetworkOfflineError
            if (r5 == 0) goto Lb1
            kotlinx.coroutines.flow.d0 r1 = r3.B
            com.quizlet.features.folders.data.g0 r2 = com.quizlet.features.folders.data.C4283g0.a
            r1.h(r2)
            goto Lca
        Lb1:
            kotlinx.coroutines.flow.d0 r3 = r3.E
            com.quizlet.features.folders.data.A0 r5 = new com.quizlet.features.folders.data.A0
            com.quizlet.features.infra.folder.menu.data.t r6 = com.quizlet.features.infra.folder.menu.data.t.a
            r5.<init>(r6)
            r0.j = r2
            r2 = 0
            r0.k = r2
            r0.l = r2
            r0.m = r4
            java.lang.Object r2 = r3.emit(r5, r0)
            if (r2 != r1) goto Lca
        Lc9:
            return r1
        Lca:
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.viewmodel.C4330k.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
