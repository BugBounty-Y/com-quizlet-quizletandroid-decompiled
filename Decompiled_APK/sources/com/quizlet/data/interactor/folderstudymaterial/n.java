package com.quizlet.data.interactor.folderstudymaterial;

import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes2.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ o l;
    public final /* synthetic */ long m;
    public final /* synthetic */ List n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(o oVar, long j, List list, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = oVar;
        this.m = j;
        this.n = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        n nVar = new n(this.l, this.m, this.n, hVar);
        nVar.k = obj;
        return nVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x004b, code lost:
    
        if (r1.emit(r3, r6) == r0) goto L17;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r7) {
        /*
            r6 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.j
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L20
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4e
        L10:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L18:
            java.lang.Object r1 = r6.k
            kotlinx.coroutines.flow.j r1 = (kotlinx.coroutines.flow.InterfaceC5002j) r1
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L39
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r6.k
            r1 = r7
            kotlinx.coroutines.flow.j r1 = (kotlinx.coroutines.flow.InterfaceC5002j) r1
            r6.k = r1
            r6.j = r3
            long r3 = r6.m
            java.util.List r7 = r6.n
            com.quizlet.data.interactor.folderstudymaterial.o r5 = r6.l
            java.lang.Object r7 = com.quizlet.data.interactor.folderstudymaterial.o.a(r5, r3, r7, r6)
            if (r7 != r0) goto L39
            goto L4d
        L39:
            java.util.List r7 = (java.util.List) r7
            if (r7 == 0) goto L4e
            kotlin.r r3 = new kotlin.r
            r3.<init>(r7)
            r7 = 0
            r6.k = r7
            r6.j = r2
            java.lang.Object r7 = r1.emit(r3, r6)
            if (r7 != r0) goto L4e
        L4d:
            return r0
        L4e:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folderstudymaterial.n.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
