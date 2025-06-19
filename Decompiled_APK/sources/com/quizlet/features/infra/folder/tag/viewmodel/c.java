package com.quizlet.features.infra.folder.tag.viewmodel;

import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public Object j;
    public d k;
    public List l;
    public int m;
    public final /* synthetic */ d n;
    public final /* synthetic */ List o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(d dVar, List list, h hVar) {
        super(2, hVar);
        this.n = dVar;
        this.o = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:31:0x00b9, code lost:
    
        if (r1.emit(r3, r14) == r0) goto L32;
     */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0090  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r15) {
        /*
            r14 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r14.m
            r2 = 0
            java.util.List r3 = r14.o
            r4 = 3
            r5 = 2
            r6 = 1
            com.quizlet.features.infra.folder.tag.viewmodel.d r7 = r14.n
            if (r1 == 0) goto L33
            if (r1 == r6) goto L2b
            if (r1 == r5) goto L21
            if (r1 != r4) goto L19
            androidx.glance.appwidget.protobuf.Z.e(r15)
            goto Lbc
        L19:
            java.lang.IllegalStateException r15 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r15.<init>(r0)
            throw r15
        L21:
            java.util.List r3 = r14.l
            com.quizlet.features.infra.folder.tag.viewmodel.d r1 = r14.k
            java.lang.Object r5 = r14.j
            androidx.glance.appwidget.protobuf.Z.e(r15)
            goto L82
        L2b:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            kotlin.r r15 = (kotlin.r) r15
            java.lang.Object r15 = r15.a
            goto L44
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            com.quizlet.data.interactor.course.a r15 = r7.b
            long r8 = r7.f
            r14.m = r6
            java.lang.Object r15 = r15.h(r8, r3, r14)
            if (r15 != r0) goto L44
            goto Lbb
        L44:
            kotlin.p r1 = kotlin.r.b
            boolean r1 = r15 instanceof kotlin.q
            if (r1 != 0) goto L8a
            r1 = r15
            java.util.List r1 = (java.util.List) r1
            kotlinx.coroutines.flow.s0 r6 = r7.i
        L4f:
            java.lang.Object r8 = r6.getValue()
            r9 = r8
            com.quizlet.features.infra.folder.tag.screenstates.k r9 = (com.quizlet.features.infra.folder.tag.screenstates.k) r9
            com.quizlet.features.infra.folder.tag.screenstates.k r9 = new com.quizlet.features.infra.folder.tag.screenstates.k
            r10 = 15
            r9.<init>(r2, r2, r10)
            boolean r8 = r6.k(r8, r9)
            if (r8 == 0) goto L4f
            java.util.ArrayList r6 = r7.g
            r6.clear()
            kotlinx.coroutines.flow.d0 r6 = r7.j
            com.quizlet.features.infra.folder.tag.screenstates.b r8 = new com.quizlet.features.infra.folder.tag.screenstates.b
            long r9 = r7.f
            r8.<init>(r9, r1)
            r14.j = r15
            r14.k = r7
            r14.l = r3
            r14.m = r5
            java.lang.Object r1 = r6.emit(r8, r14)
            if (r1 != r0) goto L80
            goto Lbb
        L80:
            r5 = r15
            r1 = r7
        L82:
            com.quizlet.eventlogger.features.folder.FolderLogger r15 = r1.e
            long r8 = r1.f
            r15.a(r8, r3)
            r15 = r5
        L8a:
            java.lang.Throwable r1 = kotlin.r.a(r15)
            if (r1 == 0) goto Lbc
            kotlinx.coroutines.flow.s0 r1 = r7.i
        L92:
            java.lang.Object r3 = r1.getValue()
            r8 = r3
            com.quizlet.features.infra.folder.tag.screenstates.k r8 = (com.quizlet.features.infra.folder.tag.screenstates.k) r8
            r11 = 0
            r12 = 0
            r9 = 0
            r10 = 0
            r13 = 11
            com.quizlet.features.infra.folder.tag.screenstates.k r5 = com.quizlet.features.infra.folder.tag.screenstates.k.a(r8, r9, r10, r11, r12, r13)
            boolean r3 = r1.k(r3, r5)
            if (r3 == 0) goto L92
            kotlinx.coroutines.flow.d0 r1 = r7.j
            com.quizlet.features.infra.folder.tag.screenstates.a r3 = com.quizlet.features.infra.folder.tag.screenstates.a.a
            r14.j = r15
            r14.k = r2
            r14.l = r2
            r14.m = r4
            java.lang.Object r15 = r1.emit(r3, r14)
            if (r15 != r0) goto Lbc
        Lbb:
            return r0
        Lbc:
            kotlin.Unit r15 = kotlin.Unit.a
            return r15
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.folder.tag.viewmodel.c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
