package com.quizlet.quizletandroid.ui.common.ads;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ E l;
    public final /* synthetic */ int m;
    public final /* synthetic */ String n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(E e, int i, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = e;
        this.m = i;
        this.n = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        u uVar = new u(this.l, this.m, this.n, hVar);
        uVar.k = obj;
        return uVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((u) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x004b, code lost:
    
        if (r1.emit(r3, r5) == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.j
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L24
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4e
        L10:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L18:
            java.lang.Object r1 = r5.k
            kotlinx.coroutines.flow.j r1 = (kotlinx.coroutines.flow.InterfaceC5002j) r1
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.r r6 = (kotlin.r) r6
            java.lang.Object r6 = r6.a
            goto L3d
        L24:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r5.k
            r1 = r6
            kotlinx.coroutines.flow.j r1 = (kotlinx.coroutines.flow.InterfaceC5002j) r1
            r5.k = r1
            r5.j = r3
            com.quizlet.quizletandroid.ui.common.ads.E r6 = r5.l
            int r3 = r5.m
            java.lang.String r4 = r5.n
            java.lang.Object r6 = com.quizlet.quizletandroid.ui.common.ads.E.a(r6, r3, r4, r5)
            if (r6 != r0) goto L3d
            goto L4d
        L3d:
            kotlin.r r3 = new kotlin.r
            r3.<init>(r6)
            r6 = 0
            r5.k = r6
            r5.j = r2
            java.lang.Object r6 = r1.emit(r3, r5)
            if (r6 != r0) goto L4e
        L4d:
            return r0
        L4e:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.common.ads.u.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
