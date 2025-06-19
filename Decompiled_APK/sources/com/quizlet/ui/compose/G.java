package com.quizlet.ui.compose;

import androidx.compose.animation.core.C0238e;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class G extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0238e k;
    public final /* synthetic */ androidx.compose.ui.geometry.b l;
    public final /* synthetic */ C0238e m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(C0238e c0238e, androidx.compose.ui.geometry.b bVar, C0238e c0238e2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0238e;
        this.l = bVar;
        this.m = c0238e2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new G(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((G) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0060, code lost:
    
        if (r8.f(r1, r7) == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r8) {
        /*
            r7 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.j
            androidx.compose.ui.geometry.b r2 = r7.l
            r3 = 2
            r4 = 1
            if (r1 == 0) goto L1e
            if (r1 == r4) goto L1a
            if (r1 != r3) goto L12
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L63
        L12:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L42
        L1e:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            androidx.compose.animation.core.e r8 = r7.k
            java.lang.Object r1 = r8.d()
            java.lang.Number r1 = (java.lang.Number) r1
            float r1 = r1.floatValue()
            long r5 = r2.a
            float r5 = androidx.compose.ui.geometry.b.d(r5)
            float r5 = r5 + r1
            java.lang.Float r1 = new java.lang.Float
            r1.<init>(r5)
            r7.j = r4
            java.lang.Object r8 = r8.f(r1, r7)
            if (r8 != r0) goto L42
            goto L62
        L42:
            androidx.compose.animation.core.e r8 = r7.m
            java.lang.Object r1 = r8.d()
            java.lang.Number r1 = (java.lang.Number) r1
            float r1 = r1.floatValue()
            long r4 = r2.a
            float r2 = androidx.compose.ui.geometry.b.e(r4)
            float r2 = r2 + r1
            java.lang.Float r1 = new java.lang.Float
            r1.<init>(r2)
            r7.j = r3
            java.lang.Object r8 = r8.f(r1, r7)
            if (r8 != r0) goto L63
        L62:
            return r0
        L63:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.ui.compose.G.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
