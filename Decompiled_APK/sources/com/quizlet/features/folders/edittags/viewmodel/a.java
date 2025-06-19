package com.quizlet.features.folders.edittags.viewmodel;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(c cVar, h hVar) {
        super(2, hVar);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x006a, code lost:
    
        if (r6.emit(r10, r9) != r0) goto L28;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.j
            com.quizlet.features.folders.edittags.viewmodel.c r2 = r9.k
            r3 = 3
            r4 = 2
            r5 = 1
            kotlinx.coroutines.flow.d0 r6 = r2.h
            if (r1 == 0) goto L27
            if (r1 == r5) goto L23
            if (r1 == r4) goto L1f
            if (r1 != r3) goto L17
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L6d
        L17:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L1f:
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Exception -> L62
            goto L48
        L23:
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Exception -> L62
            goto L3d
        L27:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            androidx.work.impl.model.e r10 = r2.c     // Catch: java.lang.Exception -> L62
            java.lang.Long r1 = r2.i     // Catch: java.lang.Exception -> L62
            if (r1 == 0) goto L5a
            long r7 = r1.longValue()     // Catch: java.lang.Exception -> L62
            r9.j = r5     // Catch: java.lang.Exception -> L62
            java.lang.Object r10 = r10.u(r7, r9)     // Catch: java.lang.Exception -> L62
            if (r10 != r0) goto L3d
            goto L6c
        L3d:
            java.lang.Boolean r10 = java.lang.Boolean.TRUE     // Catch: java.lang.Exception -> L62
            r9.j = r4     // Catch: java.lang.Exception -> L62
            java.lang.Object r10 = r6.emit(r10, r9)     // Catch: java.lang.Exception -> L62
            if (r10 != r0) goto L48
            goto L6c
        L48:
            com.quizlet.eventlogger.features.folder.FolderLogger r10 = r2.e     // Catch: java.lang.Exception -> L62
            long r4 = r2.f     // Catch: java.lang.Exception -> L62
            kotlinx.coroutines.flow.s0 r1 = r2.g     // Catch: java.lang.Exception -> L62
            java.lang.Object r1 = r1.getValue()     // Catch: java.lang.Exception -> L62
            com.quizlet.features.folders.edittags.data.g r1 = (com.quizlet.features.folders.edittags.data.g) r1     // Catch: java.lang.Exception -> L62
            java.lang.String r1 = r1.a     // Catch: java.lang.Exception -> L62
            r10.t(r4, r1)     // Catch: java.lang.Exception -> L62
            goto L6d
        L5a:
            java.lang.String r10 = "Required value was null."
            java.lang.IllegalArgumentException r1 = new java.lang.IllegalArgumentException     // Catch: java.lang.Exception -> L62
            r1.<init>(r10)     // Catch: java.lang.Exception -> L62
            throw r1     // Catch: java.lang.Exception -> L62
        L62:
            java.lang.Boolean r10 = java.lang.Boolean.FALSE
            r9.j = r3
            java.lang.Object r10 = r6.emit(r10, r9)
            if (r10 != r0) goto L6d
        L6c:
            return r0
        L6d:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.edittags.viewmodel.a.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
