package com.quizlet.edgy.ui.viewmodel;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ M k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(M m, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = m;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x008d, code lost:
    
        if (com.quizlet.edgy.ui.viewmodel.M.B(r4, r8) == r0) goto L22;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) throws java.lang.Throwable {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.j
            r2 = 2
            r3 = 1
            com.quizlet.edgy.ui.viewmodel.M r4 = r8.k
            if (r1 == 0) goto L1f
            if (r1 == r3) goto L1b
            if (r1 != r2) goto L13
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L90
        L13:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L1b:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L31
        L1f:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.data.interactor.course.a r9 = r4.h
            r8.j = r3
            java.lang.Object r9 = r9.b
            com.quizlet.data.repository.course.membership.c r9 = (com.quizlet.data.repository.course.membership.c) r9
            java.lang.Object r9 = r9.h(r8)
            if (r9 != r0) goto L31
            goto L8f
        L31:
            java.util.List r9 = (java.util.List) r9
            boolean r1 = r9.isEmpty()
            if (r1 != 0) goto L87
            r4.getClass()
            java.lang.Object r0 = kotlin.collections.CollectionsKt.L(r9)
            com.quizlet.data.model.K r0 = (com.quizlet.data.model.K) r0
            com.quizlet.data.model.School r0 = r0.a
            com.quizlet.edgy.ui.recyclerview.adapter.i r0 = com.google.android.gms.internal.mlkit_vision_document_scanner.P6.a(r0)
            r4.k = r0
            java.util.ArrayList r0 = r4.o
            r0.clear()
            java.util.ArrayList r1 = new java.util.ArrayList
            r2 = 10
            int r2 = kotlin.collections.C.q(r9, r2)
            r1.<init>(r2)
            java.util.Iterator r9 = r9.iterator()
        L5e:
            boolean r2 = r9.hasNext()
            if (r2 == 0) goto L80
            java.lang.Object r2 = r9.next()
            com.quizlet.data.model.K r2 = (com.quizlet.data.model.K) r2
            com.quizlet.data.model.Course r2 = r2.b
            java.lang.String r3 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r3)
            com.quizlet.edgy.ui.recyclerview.adapter.d r3 = new com.quizlet.edgy.ui.recyclerview.adapter.d
            java.lang.String r5 = r2.e
            long r6 = r2.a
            java.lang.String r2 = r2.b
            r3.<init>(r6, r2, r5)
            r1.add(r3)
            goto L5e
        L80:
            r0.addAll(r1)
            r4.D()
            goto L90
        L87:
            r8.j = r2
            java.lang.Object r9 = com.quizlet.edgy.ui.viewmodel.M.B(r4, r8)
            if (r9 != r0) goto L90
        L8f:
            return r0
        L90:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.edgy.ui.viewmodel.C.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
