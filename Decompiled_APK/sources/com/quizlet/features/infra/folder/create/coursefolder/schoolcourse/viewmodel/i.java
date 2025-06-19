package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Object j;
    public int k;
    public final /* synthetic */ o l;
    public final /* synthetic */ com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(o oVar, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c cVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = oVar;
        this.m = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x005b  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) throws java.lang.Throwable {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.k
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o r2 = r8.l
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L24
            if (r1 == r4) goto L1c
            if (r1 != r3) goto L14
            java.lang.Object r0 = r8.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L54
        L14:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            kotlin.r r9 = (kotlin.r) r9
            java.lang.Object r9 = r9.a
            goto L34
        L24:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r8.k = r4
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c r9 = r8.m
            com.onetrust.otpublishers.headless.UI.fragment.q r1 = r2.e
            java.lang.Object r9 = r1.s(r9, r8)
            if (r9 != r0) goto L34
            goto L52
        L34:
            kotlin.p r1 = kotlin.r.b
            boolean r1 = r9 instanceof kotlin.q
            if (r1 != 0) goto L55
            r1 = r9
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c r1 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.c) r1
            kotlinx.coroutines.flow.d0 r4 = r2.k
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.a r5 = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.a
            long r6 = r1.a
            java.lang.String r1 = r1.b
            r5.<init>(r6, r1)
            r8.j = r9
            r8.k = r3
            java.lang.Object r1 = r4.emit(r5, r8)
            if (r1 != r0) goto L53
        L52:
            return r0
        L53:
            r0 = r9
        L54:
            r9 = r0
        L55:
            java.lang.Throwable r9 = kotlin.r.a(r9)
            if (r9 == 0) goto L63
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a r9 = com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.a.d
            r0 = 0
            r1 = 13
            com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o.F(r2, r0, r9, r1)
        L63:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.i.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
