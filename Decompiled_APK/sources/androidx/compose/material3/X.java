package androidx.compose.material3;

import androidx.compose.animation.core.C0238e;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class X extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0238e k;
    public final /* synthetic */ float l;
    public final /* synthetic */ boolean m;
    public final /* synthetic */ Y n;
    public final /* synthetic */ androidx.compose.foundation.interaction.j o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public X(C0238e c0238e, float f, boolean z, Y y, androidx.compose.foundation.interaction.j jVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0238e;
        this.l = f;
        this.m = z;
        this.n = y;
        this.o = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new X(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((X) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x0042, code lost:
    
        if (r8.f(r1, r7) == r0) goto L32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x0096, code lost:
    
        if (androidx.compose.material3.internal.A.a(r8, r4, r1, r7.o, r7) == r0) goto L32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x0098, code lost:
    
        return r0;
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
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L1a
            if (r1 == r3) goto L15
            if (r1 != r2) goto Ld
            goto L15
        Ld:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r0)
            throw r8
        L15:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L99
        L1a:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            androidx.compose.animation.core.e r8 = r7.k
            androidx.compose.runtime.a0 r1 = r8.e
            androidx.compose.runtime.L0 r1 = (androidx.compose.runtime.L0) r1
            java.lang.Object r1 = r1.getValue()
            androidx.compose.ui.unit.e r1 = (androidx.compose.ui.unit.e) r1
            float r1 = r1.a
            float r4 = r7.l
            boolean r1 = androidx.compose.ui.unit.e.a(r1, r4)
            if (r1 != 0) goto L99
            boolean r1 = r7.m
            if (r1 != 0) goto L45
            androidx.compose.ui.unit.e r1 = new androidx.compose.ui.unit.e
            r1.<init>(r4)
            r7.j = r3
            java.lang.Object r8 = r8.f(r1, r7)
            if (r8 != r0) goto L99
            goto L98
        L45:
            androidx.compose.runtime.a0 r1 = r8.e
            androidx.compose.runtime.L0 r1 = (androidx.compose.runtime.L0) r1
            java.lang.Object r1 = r1.getValue()
            androidx.compose.ui.unit.e r1 = (androidx.compose.ui.unit.e) r1
            float r1 = r1.a
            androidx.compose.material3.Y r3 = r7.n
            float r5 = r3.b
            boolean r5 = androidx.compose.ui.unit.e.a(r1, r5)
            if (r5 == 0) goto L63
            androidx.compose.foundation.interaction.o r1 = new androidx.compose.foundation.interaction.o
            r5 = 0
            r1.<init>(r5)
            goto L8e
        L63:
            float r5 = r3.d
            boolean r5 = androidx.compose.ui.unit.e.a(r1, r5)
            if (r5 == 0) goto L71
            androidx.compose.foundation.interaction.h r1 = new androidx.compose.foundation.interaction.h
            r1.<init>()
            goto L8e
        L71:
            float r5 = r3.c
            boolean r5 = androidx.compose.ui.unit.e.a(r1, r5)
            if (r5 == 0) goto L7f
            androidx.compose.foundation.interaction.d r1 = new androidx.compose.foundation.interaction.d
            r1.<init>()
            goto L8e
        L7f:
            float r3 = r3.e
            boolean r1 = androidx.compose.ui.unit.e.a(r1, r3)
            if (r1 == 0) goto L8d
            androidx.compose.foundation.interaction.b r1 = new androidx.compose.foundation.interaction.b
            r1.<init>()
            goto L8e
        L8d:
            r1 = 0
        L8e:
            r7.j = r2
            androidx.compose.foundation.interaction.j r2 = r7.o
            java.lang.Object r8 = androidx.compose.material3.internal.A.a(r8, r4, r1, r2, r7)
            if (r8 != r0) goto L99
        L98:
            return r0
        L99:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.X.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
