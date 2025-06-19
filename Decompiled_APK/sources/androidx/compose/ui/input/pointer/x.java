package androidx.compose.ui.input.pointer;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class x extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ long k;
    public final /* synthetic */ z l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public x(long j, z zVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j;
        this.l = zVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new x(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((x) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0034, code lost:
    
        if (kotlinx.coroutines.E.n(1, r10) == r0) goto L15;
     */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r11) {
        /*
            r10 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r10.j
            r2 = 1
            long r4 = r10.k
            r6 = 2
            r7 = 1
            if (r1 == 0) goto L20
            if (r1 == r7) goto L1c
            if (r1 != r6) goto L14
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L37
        L14:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L1c:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L2e
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            long r8 = r4 - r2
            r10.j = r7
            java.lang.Object r11 = kotlinx.coroutines.E.n(r8, r10)
            if (r11 != r0) goto L2e
            goto L36
        L2e:
            r10.j = r6
            java.lang.Object r11 = kotlinx.coroutines.E.n(r2, r10)
            if (r11 != r0) goto L37
        L36:
            return r0
        L37:
            androidx.compose.ui.input.pointer.z r11 = r10.l
            kotlinx.coroutines.l r11 = r11.c
            if (r11 == 0) goto L4b
            kotlin.p r0 = kotlin.r.b
            androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException r0 = new androidx.compose.ui.input.pointer.PointerEventTimeoutCancellationException
            r0.<init>(r4)
            kotlin.q r0 = androidx.glance.appwidget.protobuf.Z.b(r0)
            r11.resumeWith(r0)
        L4b:
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.input.pointer.x.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
