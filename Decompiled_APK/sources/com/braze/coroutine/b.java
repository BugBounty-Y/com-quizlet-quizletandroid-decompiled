package com.braze.coroutine;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class b extends i implements Function2 {
    public int a;
    public /* synthetic */ Object b;
    public final /* synthetic */ Number c;
    public final /* synthetic */ Function1 d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(Number number, Function1 function1, h hVar) {
        super(2, hVar);
        this.c = number;
        this.d = function1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        b bVar = new b(this.c, this.d, hVar);
        bVar.b = obj;
        return bVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x004a, code lost:
    
        if (r7.invoke(r6) == r0) goto L17;
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
            int r1 = r6.a
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L20
            if (r1 == r3) goto L18
            if (r1 != r2) goto L10
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4d
        L10:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L18:
            java.lang.Object r1 = r6.b
            kotlinx.coroutines.C r1 = (kotlinx.coroutines.C) r1
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L39
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r6.b
            r1 = r7
            kotlinx.coroutines.C r1 = (kotlinx.coroutines.C) r1
            java.lang.Number r7 = r6.c
            long r4 = r7.longValue()
            r6.b = r1
            r6.a = r3
            java.lang.Object r7 = kotlinx.coroutines.E.n(r4, r6)
            if (r7 != r0) goto L39
            goto L4c
        L39:
            boolean r7 = kotlinx.coroutines.E.x(r1)
            if (r7 == 0) goto L4d
            kotlin.jvm.functions.Function1 r7 = r6.d
            r1 = 0
            r6.b = r1
            r6.a = r2
            java.lang.Object r7 = r7.invoke(r6)
            if (r7 != r0) goto L4d
        L4c:
            return r0
        L4d:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.coroutine.b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
