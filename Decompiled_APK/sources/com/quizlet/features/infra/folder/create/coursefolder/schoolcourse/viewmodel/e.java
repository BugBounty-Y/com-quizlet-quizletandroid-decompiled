package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public int k;
    public final /* synthetic */ o l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(o oVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = oVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x006a, code lost:
    
        if (r1.emit(r2, r9) == r0) goto L22;
     */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0051  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.k
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o r2 = r9.l
            java.lang.String r3 = ""
            r4 = 0
            r6 = 3
            r7 = 2
            r8 = 1
            if (r1 == 0) goto L2d
            if (r1 == r8) goto L29
            if (r1 == r7) goto L21
            if (r1 != r6) goto L19
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L6d
        L19:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlin.r r10 = (kotlin.r) r10
            java.lang.Object r10 = r10.a
            goto L4b
        L29:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L40
        L2d:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlinx.coroutines.flow.d0 r10 = r2.k
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.a r1 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.a
            r1.<init>(r4, r3)
            r9.k = r8
            java.lang.Object r10 = r10.emit(r1, r9)
            if (r10 != r0) goto L40
            goto L6c
        L40:
            r9.k = r7
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.i r10 = r2.c
            java.lang.Object r10 = r10.c(r9)
            if (r10 != r0) goto L4b
            goto L6c
        L4b:
            kotlin.p r1 = kotlin.r.b
            boolean r1 = r10 instanceof kotlin.q
            if (r1 != 0) goto L6d
            r1 = r10
            kotlin.Unit r1 = (kotlin.Unit) r1
            r1 = 0
            r2.m = r1
            r1 = 0
            r2.B(r1)
            kotlinx.coroutines.flow.d0 r1 = r2.j
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.c r2 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.c
            r2.<init>(r4, r3)
            r9.j = r10
            r9.k = r6
            java.lang.Object r10 = r1.emit(r2, r9)
            if (r10 != r0) goto L6d
        L6c:
            return r0
        L6d:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.e.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
