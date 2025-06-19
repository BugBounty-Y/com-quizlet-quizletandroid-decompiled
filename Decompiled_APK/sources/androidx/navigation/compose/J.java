package androidx.navigation.compose;

import androidx.compose.animation.core.C0247i0;
import androidx.navigation.C1291m;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class J extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ float k;
    public final /* synthetic */ C0247i0 l;
    public final /* synthetic */ C1291m m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J(float f, C0247i0 c0247i0, C1291m c1291m, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = f;
        this.l = c0247i0;
        this.m = c1291m;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new J(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((J) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:29:0x0078, code lost:
    
        if (r8 == r0) goto L30;
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
            androidx.compose.animation.core.i0 r2 = r7.l
            r3 = 0
            float r4 = r7.k
            r5 = 2
            r6 = 1
            if (r1 == 0) goto L21
            if (r1 == r6) goto L1d
            if (r1 != r5) goto L15
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L7b
        L15:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L1d:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L39
        L21:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            int r8 = (r4 > r3 ? 1 : (r4 == r3 ? 0 : -1))
            if (r8 <= 0) goto L39
            r7.j = r6
            androidx.compose.runtime.a0 r8 = r2.c
            androidx.compose.runtime.L0 r8 = (androidx.compose.runtime.L0) r8
            java.lang.Object r8 = r8.getValue()
            java.lang.Object r8 = r2.b0(r4, r8, r7)
            if (r8 != r0) goto L39
            goto L7a
        L39:
            int r8 = (r4 > r3 ? 1 : (r4 == r3 ? 0 : -1))
            if (r8 != 0) goto L7b
            r7.j = r5
            androidx.compose.animation.core.E0 r8 = r2.f
            if (r8 != 0) goto L46
            kotlin.Unit r8 = kotlin.Unit.a
            goto L78
        L46:
            androidx.compose.runtime.a0 r1 = r2.d
            androidx.compose.runtime.L0 r1 = (androidx.compose.runtime.L0) r1
            java.lang.Object r1 = r1.getValue()
            androidx.navigation.m r3 = r7.m
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r1, r3)
            if (r1 == 0) goto L67
            androidx.compose.runtime.a0 r1 = r2.c
            androidx.compose.runtime.L0 r1 = (androidx.compose.runtime.L0) r1
            java.lang.Object r1 = r1.getValue()
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r1, r3)
            if (r1 == 0) goto L67
            kotlin.Unit r8 = kotlin.Unit.a
            goto L78
        L67:
            androidx.compose.animation.core.f0 r1 = new androidx.compose.animation.core.f0
            r4 = 0
            r1.<init>(r2, r8, r3, r4)
            androidx.compose.animation.core.W r8 = r2.l
            java.lang.Object r8 = androidx.compose.animation.core.W.a(r8, r1, r7)
            if (r8 != r0) goto L76
            goto L78
        L76:
            kotlin.Unit r8 = kotlin.Unit.a
        L78:
            if (r8 != r0) goto L7b
        L7a:
            return r0
        L7b:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.navigation.compose.J.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
