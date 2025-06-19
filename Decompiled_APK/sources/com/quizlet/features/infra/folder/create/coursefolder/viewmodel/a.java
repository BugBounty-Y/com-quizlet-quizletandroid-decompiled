package com.quizlet.features.infra.folder.create.coursefolder.viewmodel;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public Object j;
    public int k;
    public final /* synthetic */ e l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(e eVar, h hVar) {
        super(2, hVar);
        this.l = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x006b, code lost:
    
        if (r2.emit(r1, r7) == r0) goto L34;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0078, code lost:
    
        if (r2.emit(r1, r7) == r0) goto L34;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.k
            com.quizlet.features.infra.folder.create.coursefolder.viewmodel.e r2 = r7.l
            r3 = 1
            r4 = 3
            r5 = 2
            if (r1 == 0) goto L25
            if (r1 == r3) goto L1d
            if (r1 == r5) goto L11
            if (r1 != r4) goto L15
        L11:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L7b
        L15:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1d:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            kotlin.r r8 = (kotlin.r) r8
            java.lang.Object r8 = r8.a
            goto L33
        L25:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r7.k = r3
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i r8 = r2.b
            java.lang.Object r8 = r8.d(r7)
            if (r8 != r0) goto L33
            goto L7a
        L33:
            kotlin.p r1 = kotlin.r.b
            boolean r1 = r8 instanceof kotlin.q
            if (r1 != 0) goto L48
            r1 = r8
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e r1 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e) r1
            java.lang.String r6 = ""
            if (r1 == 0) goto L44
            java.lang.String r1 = r1.b
            if (r1 != 0) goto L45
        L44:
            r1 = r6
        L45:
            r2.C(r1, r6, r3)
        L48:
            java.lang.Throwable r1 = kotlin.r.a(r8)
            if (r1 == 0) goto L7b
            boolean r3 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3746v6.b(r1)
            kotlinx.coroutines.flow.d0 r2 = r2.p
            if (r3 != 0) goto L6e
            java.lang.Throwable r1 = r1.getCause()
            boolean r1 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3746v6.b(r1)
            if (r1 == 0) goto L61
            goto L6e
        L61:
            com.quizlet.features.infra.folder.create.coursefolder.data.a r1 = com.quizlet.features.infra.folder.create.coursefolder.data.a.a
            r7.j = r8
            r7.k = r4
            java.lang.Object r8 = r2.emit(r1, r7)
            if (r8 != r0) goto L7b
            goto L7a
        L6e:
            com.quizlet.features.infra.folder.create.coursefolder.data.b r1 = com.quizlet.features.infra.folder.create.coursefolder.data.b.a
            r7.j = r8
            r7.k = r5
            java.lang.Object r8 = r2.emit(r1, r7)
            if (r8 != r0) goto L7b
        L7a:
            return r0
        L7b:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.create.coursefolder.viewmodel.a.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
