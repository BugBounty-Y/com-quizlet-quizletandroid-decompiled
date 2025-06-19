package androidx.navigation.compose;

import androidx.compose.animation.core.C0247i0;
import androidx.compose.animation.core.E0;
import androidx.navigation.C1291m;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class K extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0247i0 l;
    public final /* synthetic */ C1291m m;
    public final /* synthetic */ E0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(C0247i0 c0247i0, C1291m c1291m, E0 e0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0247i0;
        this.m = c1291m;
        this.n = e0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        K k = new K(this.l, this.m, this.n, hVar);
        k.k = obj;
        return k;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((K) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x004c, code lost:
    
        if (r14 == r0) goto L23;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x0081, code lost:
    
        if (androidx.compose.animation.core.AbstractC0240f.e(r7, com.skydoves.balloon.internals.DefinitionKt.NO_Float_VALUE, r9, r10, r13, 4) == r0) goto L23;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x0083, code lost:
    
        return r0;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r14) {
        /*
            r13 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r13.j
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L19
            if (r1 == r3) goto L15
            if (r1 != r2) goto Ld
            goto L15
        Ld:
            java.lang.IllegalStateException r14 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r14.<init>(r0)
            throw r14
        L15:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L84
        L19:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            java.lang.Object r14 = r13.k
            kotlinx.coroutines.C r14 = (kotlinx.coroutines.C) r14
            androidx.compose.animation.core.i0 r1 = r13.l
            androidx.compose.runtime.a0 r4 = r1.d
            androidx.compose.runtime.L0 r4 = (androidx.compose.runtime.L0) r4
            java.lang.Object r4 = r4.getValue()
            androidx.navigation.m r5 = r13.m
            boolean r4 = kotlin.jvm.internal.Intrinsics.b(r4, r5)
            r6 = 0
            if (r4 != 0) goto L4f
            r13.j = r3
            androidx.compose.animation.core.E0 r14 = r1.f
            if (r14 != 0) goto L3c
            kotlin.Unit r14 = kotlin.Unit.a
            goto L4c
        L3c:
            androidx.compose.animation.core.a0 r2 = new androidx.compose.animation.core.a0
            r2.<init>(r1, r14, r5, r6)
            androidx.compose.animation.core.W r14 = r1.l
            java.lang.Object r14 = androidx.compose.animation.core.W.a(r14, r2, r13)
            if (r14 != r0) goto L4a
            goto L4c
        L4a:
            kotlin.Unit r14 = kotlin.Unit.a
        L4c:
            if (r14 != r0) goto L84
            goto L83
        L4f:
            androidx.compose.animation.core.E0 r3 = r13.n
            androidx.compose.runtime.E r3 = r3.l
            java.lang.Object r3 = r3.getValue()
            java.lang.Number r3 = (java.lang.Number) r3
            long r3 = r3.longValue()
            r7 = 1000000(0xf4240, float:1.401298E-39)
            long r7 = (long) r7
            long r3 = r3 / r7
            float r7 = r1.a0()
            float r8 = r1.a0()
            float r3 = (float) r3
            float r8 = r8 * r3
            int r3 = (int) r8
            r4 = 0
            r8 = 6
            androidx.compose.animation.core.K0 r9 = androidx.compose.animation.core.AbstractC0240f.r(r3, r4, r6, r8)
            androidx.lifecycle.compose.e r10 = new androidx.lifecycle.compose.e
            r10.<init>(r14, r1, r5)
            r13.j = r2
            r8 = 0
            r12 = 4
            r11 = r13
            java.lang.Object r14 = androidx.compose.animation.core.AbstractC0240f.e(r7, r8, r9, r10, r11, r12)
            if (r14 != r0) goto L84
        L83:
            return r0
        L84:
            kotlin.Unit r14 = kotlin.Unit.a
            return r14
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.navigation.compose.K.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
