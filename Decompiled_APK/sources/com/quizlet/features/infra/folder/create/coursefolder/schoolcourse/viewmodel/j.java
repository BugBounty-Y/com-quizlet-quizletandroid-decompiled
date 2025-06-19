package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ o k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(o oVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x003a, code lost:
    
        if (r7 == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) throws java.lang.Throwable {
        /*
            r6 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.j
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o r2 = r6.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L22
            if (r1 == r4) goto L1e
            if (r1 != r3) goto L16
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r7 = r7.a
            goto L3d
        L16:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L30
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r6.j = r4
            r4 = 600(0x258, double:2.964E-321)
            java.lang.Object r7 = kotlinx.coroutines.E.n(r4, r6)
            if (r7 != r0) goto L30
            goto L3c
        L30:
            r6.j = r3
            java.lang.String r7 = r6.l
            com.google.firebase.messaging.p r1 = r2.d
            java.io.Serializable r7 = r1.x(r7, r6)
            if (r7 != r0) goto L3d
        L3c:
            return r0
        L3d:
            kotlin.p r0 = kotlin.r.b
            boolean r0 = r7 instanceof kotlin.q
            r1 = 12
            if (r0 != 0) goto L4d
            r0 = r7
            java.util.List r0 = (java.util.List) r0
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a r3 = com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.b
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o.F(r2, r0, r3, r1)
        L4d:
            java.lang.Throwable r0 = kotlin.r.a(r7)
            if (r0 == 0) goto L7b
            java.lang.Throwable r7 = kotlin.r.a(r7)
            boolean r0 = r7 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.NoCourseException
            if (r0 == 0) goto L69
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.NoCourseException r7 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.NoCourseException) r7
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c r7 = r7.a
            java.util.List r7 = kotlin.collections.A.b(r7)
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a r0 = com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.c
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o.F(r2, r7, r0, r1)
            goto L7b
        L69:
            boolean r7 = r7 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.EmptyQueryException
            if (r7 == 0) goto L73
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f r7 = r2.m
            r2.A(r7)
            goto L7b
        L73:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a r7 = com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.d
            r0 = 13
            r1 = 0
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o.F(r2, r1, r7, r0)
        L7b:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.j.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
