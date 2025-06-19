package kotlinx.coroutines;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class p0 extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public t0 k;
    public kotlinx.coroutines.internal.i l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ q0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p0(kotlin.coroutines.h hVar, q0 q0Var) {
        super(2, hVar);
        this.o = q0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        p0 p0Var = new p0(hVar, this.o);
        p0Var.n = obj;
        return p0Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((p0) create((kotlin.sequences.i) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0067  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:22:0x0069 -> B:25:0x007e). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r6) {
        /*
            r5 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r5.m
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L24
            if (r1 == r3) goto L20
            if (r1 != r2) goto L18
            kotlinx.coroutines.internal.i r1 = r5.l
            kotlinx.coroutines.t0 r3 = r5.k
            java.lang.Object r4 = r5.n
            kotlin.sequences.i r4 = (kotlin.sequences.i) r4
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L7e
        L18:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L20:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L83
        L24:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r5.n
            kotlin.sequences.i r6 = (kotlin.sequences.i) r6
            kotlinx.coroutines.q0 r1 = r5.o
            r1.getClass()
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r4 = kotlinx.coroutines.q0.a
            java.lang.Object r1 = r4.get(r1)
            boolean r4 = r1 instanceof kotlinx.coroutines.C5032p
            if (r4 == 0) goto L44
            kotlinx.coroutines.p r1 = (kotlinx.coroutines.C5032p) r1
            kotlinx.coroutines.q0 r1 = r1.e
            r5.m = r3
            r6.a(r1, r5)
            return r0
        L44:
            boolean r3 = r1 instanceof kotlinx.coroutines.InterfaceC4981e0
            if (r3 == 0) goto L83
            kotlinx.coroutines.e0 r1 = (kotlinx.coroutines.InterfaceC4981e0) r1
            kotlinx.coroutines.t0 r1 = r1.b()
            if (r1 == 0) goto L83
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r3 = kotlinx.coroutines.internal.i.a
            java.lang.Object r3 = r3.get(r1)
            java.lang.String r4 = "null cannot be cast to non-null type kotlinx.coroutines.internal.LockFreeLinkedListNode"
            kotlin.jvm.internal.Intrinsics.e(r3, r4)
            kotlinx.coroutines.internal.i r3 = (kotlinx.coroutines.internal.i) r3
            r4 = r3
            r3 = r1
            r1 = r4
            r4 = r6
        L61:
            boolean r6 = r1.equals(r3)
            if (r6 != 0) goto L83
            boolean r6 = r1 instanceof kotlinx.coroutines.C5032p
            if (r6 == 0) goto L7e
            r6 = r1
            kotlinx.coroutines.p r6 = (kotlinx.coroutines.C5032p) r6
            r5.n = r4
            r5.k = r3
            r5.l = r1
            r5.m = r2
            kotlinx.coroutines.q0 r6 = r6.e
            r4.a(r6, r5)
            kotlin.coroutines.intrinsics.a r6 = kotlin.coroutines.intrinsics.a.a
            return r0
        L7e:
            kotlinx.coroutines.internal.i r1 = r1.g()
            goto L61
        L83:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.p0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
