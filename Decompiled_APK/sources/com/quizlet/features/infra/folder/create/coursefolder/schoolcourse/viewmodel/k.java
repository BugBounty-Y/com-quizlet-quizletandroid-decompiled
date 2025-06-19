package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ o k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(o oVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x003a, code lost:
    
        if (r9 == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) throws com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.EmptyQueryException {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.j
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o r2 = r8.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L22
            if (r1 == r4) goto L1e
            if (r1 != r3) goto L16
            androidx.glance.appwidget.protobuf.Z.e(r9)
            kotlin.r r9 = (kotlin.r) r9
            java.lang.Object r9 = r9.a
            goto L3d
        L16:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L30
        L22:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r8.j = r4
            r4 = 600(0x258, double:2.964E-321)
            java.lang.Object r9 = kotlinx.coroutines.E.n(r4, r8)
            if (r9 != r0) goto L30
            goto L3c
        L30:
            r8.j = r3
            java.lang.String r9 = r8.l
            com.google.firebase.crashlytics.internal.common.j r1 = r2.b
            java.io.Serializable r9 = r1.f(r9, r8)
            if (r9 != r0) goto L3d
        L3c:
            return r0
        L3d:
            kotlin.p r0 = kotlin.r.b
            boolean r0 = r9 instanceof kotlin.q
            if (r0 != 0) goto L4f
            r3 = r9
            java.util.List r3 = (java.util.List) r3
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a r4 = com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.b
            r5 = 0
            r6 = 0
            r7 = 28
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o.G(r2, r3, r4, r5, r6, r7)
        L4f:
            java.lang.Throwable r0 = kotlin.r.a(r9)
            if (r0 == 0) goto L82
            java.lang.Throwable r9 = kotlin.r.a(r9)
            boolean r0 = r9 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.NoSchoolException
            if (r0 == 0) goto L6f
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.NoSchoolException r9 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.NoSchoolException) r9
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e r9 = r9.a
            java.util.List r3 = kotlin.collections.A.b(r9)
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a r4 = com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.c
            r5 = 0
            r6 = 0
            r7 = 28
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o.G(r2, r3, r4, r5, r6, r7)
            goto L82
        L6f:
            boolean r9 = r9 instanceof com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase.EmptyQueryException
            if (r9 == 0) goto L78
            r9 = 0
            r2.B(r9)
            goto L82
        L78:
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a r4 = com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.d
            r5 = 0
            r6 = 0
            r3 = 0
            r7 = 29
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o.G(r2, r3, r4, r5, r6, r7)
        L82:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.k.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
