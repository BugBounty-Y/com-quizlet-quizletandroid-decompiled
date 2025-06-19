package com.mayakapps.kache;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ H k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(H h, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = h;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0032, code lost:
    
        if (com.mayakapps.kache.H.d(r2, r5) == r0) goto L15;
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
            com.mayakapps.kache.H r2 = r5.k
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L35
        L12:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L2c
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r5.j = r4
            java.lang.String r6 = r5.l
            java.lang.Object r6 = com.mayakapps.kache.H.e(r2, r6, r5)
            if (r6 != r0) goto L2c
            goto L34
        L2c:
            r5.j = r3
            java.lang.Object r6 = com.mayakapps.kache.H.d(r2, r5)
            if (r6 != r0) goto L35
        L34:
            return r0
        L35:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mayakapps.kache.C.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
