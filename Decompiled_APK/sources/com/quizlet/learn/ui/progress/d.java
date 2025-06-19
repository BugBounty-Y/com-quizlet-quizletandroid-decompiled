package com.quizlet.learn.ui.progress;

import androidx.compose.runtime.F0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ f k;
    public final /* synthetic */ int l;
    public final /* synthetic */ int m;
    public final /* synthetic */ int n;
    public final /* synthetic */ Function0 o;
    public final /* synthetic */ F0 p;
    public final /* synthetic */ F0 q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(f fVar, int i, int i2, int i3, Function0 function0, F0 f0, F0 f02, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = fVar;
        this.l = i;
        this.m = i2;
        this.n = i3;
        this.o = function0;
        this.p = f0;
        this.q = f02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, this.l, this.m, this.n, this.o, this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x004a, code lost:
    
        if (kotlinx.coroutines.E.n(150, r7) == r0) goto L19;
     */
    /* JADX WARN: Removed duplicated region for block: B:22:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0067  */
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
            com.quizlet.learn.ui.progress.f r2 = r7.k
            int r3 = r7.m
            r4 = 2
            r5 = 1
            if (r1 == 0) goto L20
            if (r1 == r5) goto L1c
            if (r1 != r4) goto L14
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L4d
        L14:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L32
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.learn.ui.progress.f r8 = com.quizlet.learn.ui.progress.f.b
            if (r2 != r8) goto L32
            r7.j = r5
            r5 = 300(0x12c, double:1.48E-321)
            java.lang.Object r8 = kotlinx.coroutines.E.n(r5, r7)
            if (r8 != r0) goto L32
            goto L4c
        L32:
            int r8 = r7.l
            float r8 = (float) r8
            float r1 = (float) r3
            float r8 = r8 / r1
            androidx.compose.animation.core.K0 r1 = com.quizlet.learn.ui.progress.e.a
            androidx.compose.runtime.F0 r1 = r7.p
            r1.j(r8)
            com.quizlet.learn.ui.progress.f r8 = com.quizlet.learn.ui.progress.f.b
            if (r2 != r8) goto L4d
            r7.j = r4
            r1 = 150(0x96, double:7.4E-322)
            java.lang.Object r8 = kotlinx.coroutines.E.n(r1, r7)
            if (r8 != r0) goto L4d
        L4c:
            return r0
        L4d:
            int r8 = r7.n
            float r8 = (float) r8
            float r0 = (float) r3
            float r8 = r8 / r0
            androidx.compose.animation.core.K0 r0 = com.quizlet.learn.ui.progress.e.a
            androidx.compose.runtime.F0 r0 = r7.q
            float r1 = r0.i()
            int r1 = (r8 > r1 ? 1 : (r8 == r1 ? 0 : -1))
            if (r1 > 0) goto L67
            r0.j(r8)
            kotlin.jvm.functions.Function0 r8 = r7.o
            r8.invoke()
            goto L6a
        L67:
            r0.j(r8)
        L6a:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.learn.ui.progress.d.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
