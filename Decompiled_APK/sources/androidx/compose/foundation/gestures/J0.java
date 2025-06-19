package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class J0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public long j;
    public int k;
    public /* synthetic */ long l;
    public final /* synthetic */ L0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J0(L0 l0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = l0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        J0 j0 = new J0(this.m, hVar);
        j0.l = ((androidx.compose.ui.unit.o) obj).a;
        return j0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        long j = ((androidx.compose.ui.unit.o) obj).a;
        J0 j0 = new J0(this.m, (kotlin.coroutines.h) obj2);
        j0.l = j;
        return j0.invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x006f  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r15) {
        /*
            r14 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r14.k
            r2 = 3
            r3 = 2
            r4 = 1
            androidx.compose.foundation.gestures.L0 r5 = r14.m
            if (r1 == 0) goto L2f
            if (r1 == r4) goto L29
            if (r1 == r3) goto L21
            if (r1 != r2) goto L19
            long r0 = r14.j
            long r2 = r14.l
            androidx.glance.appwidget.protobuf.Z.e(r15)
            goto L71
        L19:
            java.lang.IllegalStateException r15 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r15.<init>(r0)
            throw r15
        L21:
            long r3 = r14.j
            long r6 = r14.l
            androidx.glance.appwidget.protobuf.Z.e(r15)
            goto L57
        L29:
            long r6 = r14.l
            androidx.glance.appwidget.protobuf.Z.e(r15)
            goto L41
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            long r6 = r14.l
            androidx.compose.ui.input.nestedscroll.e r15 = r5.f
            r14.l = r6
            r14.k = r4
            java.lang.Object r15 = r15.b(r6, r14)
            if (r15 != r0) goto L41
            goto L6e
        L41:
            androidx.compose.ui.unit.o r15 = (androidx.compose.ui.unit.o) r15
            long r8 = r15.a
            long r8 = androidx.compose.ui.unit.o.d(r6, r8)
            r14.l = r6
            r14.j = r8
            r14.k = r3
            java.lang.Object r15 = r5.b(r8, r14)
            if (r15 != r0) goto L56
            goto L6e
        L56:
            r3 = r8
        L57:
            androidx.compose.ui.unit.o r15 = (androidx.compose.ui.unit.o) r15
            long r11 = r15.a
            androidx.compose.ui.input.nestedscroll.e r8 = r5.f
            long r9 = androidx.compose.ui.unit.o.d(r3, r11)
            r14.l = r6
            r14.j = r11
            r14.k = r2
            r13 = r14
            java.lang.Object r15 = r8.a(r9, r11, r13)
            if (r15 != r0) goto L6f
        L6e:
            return r0
        L6f:
            r2 = r6
            r0 = r11
        L71:
            androidx.compose.ui.unit.o r15 = (androidx.compose.ui.unit.o) r15
            long r4 = r15.a
            long r0 = androidx.compose.ui.unit.o.d(r0, r4)
            long r0 = androidx.compose.ui.unit.o.d(r2, r0)
            androidx.compose.ui.unit.o r15 = new androidx.compose.ui.unit.o
            r15.<init>(r0)
            return r15
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.J0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
