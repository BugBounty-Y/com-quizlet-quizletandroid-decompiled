package androidx.compose.foundation;

import androidx.compose.foundation.gestures.C0326g0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0305d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public boolean j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0326g0 m;
    public final /* synthetic */ long n;
    public final /* synthetic */ androidx.compose.foundation.interaction.l o;
    public final /* synthetic */ AbstractC0368j p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0305d(C0326g0 c0326g0, long j, androidx.compose.foundation.interaction.l lVar, AbstractC0368j abstractC0368j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = c0326g0;
        this.n = j;
        this.o = lVar;
        this.p = abstractC0368j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0305d c0305d = new C0305d(this.m, this.n, this.o, this.p, hVar);
        c0305d.l = obj;
        return c0305d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0305d) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:31:0x00a4, code lost:
    
        if (r10.c(r2, r17) != r1) goto L41;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00c0, code lost:
    
        if (r10.c(r3, r17) == r1) goto L40;
     */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0084  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r18) {
        /*
            r17 = this;
            r0 = r17
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.k
            r3 = 3
            r4 = 0
            androidx.compose.foundation.j r5 = r0.p
            r6 = 5
            r7 = 4
            r8 = 2
            r9 = 1
            androidx.compose.foundation.interaction.l r10 = r0.o
            if (r2 == 0) goto L43
            if (r2 == r9) goto L39
            if (r2 == r8) goto L33
            if (r2 == r3) goto L2a
            if (r2 == r7) goto L25
            if (r2 != r6) goto L1d
            goto L25
        L1d:
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r1.<init>(r2)
            throw r1
        L25:
            androidx.glance.appwidget.protobuf.Z.e(r18)
            goto Lc3
        L2a:
            java.lang.Object r2 = r0.l
            androidx.compose.foundation.interaction.p r2 = (androidx.compose.foundation.interaction.p) r2
            androidx.glance.appwidget.protobuf.Z.e(r18)
            goto L9c
        L33:
            boolean r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r18)
            goto L82
        L39:
            java.lang.Object r2 = r0.l
            kotlinx.coroutines.j0 r2 = (kotlinx.coroutines.InterfaceC5025j0) r2
            androidx.glance.appwidget.protobuf.Z.e(r18)
            r9 = r18
            goto L68
        L43:
            androidx.glance.appwidget.protobuf.Z.e(r18)
            java.lang.Object r2 = r0.l
            kotlinx.coroutines.C r2 = (kotlinx.coroutines.C) r2
            androidx.compose.foundation.c r11 = new androidx.compose.foundation.c
            androidx.compose.foundation.j r12 = r0.p
            long r13 = r0.n
            androidx.compose.foundation.interaction.l r15 = r0.o
            r16 = 0
            r11.<init>(r12, r13, r15, r16)
            kotlinx.coroutines.y0 r2 = kotlinx.coroutines.E.A(r2, r4, r4, r11, r3)
            r0.l = r2
            r0.k = r9
            androidx.compose.foundation.gestures.g0 r9 = r0.m
            java.lang.Object r9 = r9.c(r0)
            if (r9 != r1) goto L68
            goto Lc2
        L68:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            boolean r11 = r2.a()
            if (r11 == 0) goto La7
            r0.l = r4
            r0.j = r9
            r0.k = r8
            java.lang.Object r2 = kotlinx.coroutines.E.k(r2, r0)
            if (r2 != r1) goto L81
            goto Lc2
        L81:
            r2 = r9
        L82:
            if (r2 == 0) goto Lc3
            androidx.compose.foundation.interaction.o r2 = new androidx.compose.foundation.interaction.o
            long r8 = r0.n
            r2.<init>(r8)
            androidx.compose.foundation.interaction.p r6 = new androidx.compose.foundation.interaction.p
            r6.<init>(r2)
            r0.l = r6
            r0.k = r3
            java.lang.Object r2 = r10.c(r2, r0)
            if (r2 != r1) goto L9b
            goto Lc2
        L9b:
            r2 = r6
        L9c:
            r0.l = r4
            r0.k = r7
            java.lang.Object r2 = r10.c(r2, r0)
            if (r2 != r1) goto Lc3
            goto Lc2
        La7:
            androidx.compose.foundation.interaction.o r2 = r5.z
            if (r2 == 0) goto Lc3
            if (r9 == 0) goto Lb3
            androidx.compose.foundation.interaction.p r3 = new androidx.compose.foundation.interaction.p
            r3.<init>(r2)
            goto Lb8
        Lb3:
            androidx.compose.foundation.interaction.n r3 = new androidx.compose.foundation.interaction.n
            r3.<init>(r2)
        Lb8:
            r0.l = r4
            r0.k = r6
            java.lang.Object r2 = r10.c(r3, r0)
            if (r2 != r1) goto Lc3
        Lc2:
            return r1
        Lc3:
            r5.z = r4
            kotlin.Unit r1 = kotlin.Unit.a
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.C0305d.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
