package kotlinx.coroutines.flow;

import java.io.Serializable;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class l0 implements InterfaceC5002j {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ Serializable b;
    public final /* synthetic */ Object c;

    public l0(kotlin.jvm.internal.F f, InterfaceC5002j interfaceC5002j) {
        this.b = f;
        this.c = interfaceC5002j;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(int r5, kotlin.coroutines.h r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof kotlinx.coroutines.flow.k0
            if (r0 == 0) goto L13
            r0 = r6
            kotlinx.coroutines.flow.k0 r0 = (kotlinx.coroutines.flow.k0) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.k0 r0 = new kotlinx.coroutines.flow.k0
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4d
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            if (r5 <= 0) goto L50
            java.io.Serializable r5 = r4.b
            kotlin.jvm.internal.F r5 = (kotlin.jvm.internal.F) r5
            boolean r6 = r5.a
            if (r6 != 0) goto L50
            r5.a = r3
            kotlinx.coroutines.flow.g0 r5 = kotlinx.coroutines.flow.g0.a
            r0.l = r3
            java.lang.Object r6 = r4.c
            kotlinx.coroutines.flow.j r6 = (kotlinx.coroutines.flow.InterfaceC5002j) r6
            java.lang.Object r5 = r6.emit(r5, r0)
            if (r5 != r1) goto L4d
            return r1
        L4d:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L50:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.l0.a(int, kotlin.coroutines.h):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x0018  */
    /* JADX WARN: Type inference failed for: r6v3, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object emit(java.lang.Object r5, kotlin.coroutines.h r6) {
        /*
            r4 = this;
            int r0 = r4.a
            switch(r0) {
                case 0: goto L64;
                default: goto L5;
            }
        L5:
            boolean r0 = r6 instanceof kotlinx.coroutines.flow.I
            if (r0 == 0) goto L18
            r0 = r6
            kotlinx.coroutines.flow.I r0 = (kotlinx.coroutines.flow.I) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L18
            int r1 = r1 - r2
            r0.l = r1
            goto L1d
        L18:
            kotlinx.coroutines.flow.I r0 = new kotlinx.coroutines.flow.I
            r0.<init>(r4, r6)
        L1d:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L38
            if (r2 != r3) goto L30
            java.lang.Object r5 = r0.n
            kotlinx.coroutines.flow.l0 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4d
        L30:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.n = r5
            r0.l = r3
            java.io.Serializable r6 = r4.b
            kotlin.coroutines.jvm.internal.i r6 = (kotlin.coroutines.jvm.internal.i) r6
            java.lang.Object r6 = r6.invoke(r5, r0)
            if (r6 != r1) goto L4c
            goto L57
        L4c:
            r0 = r4
        L4d:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 != 0) goto L58
            kotlin.Unit r1 = kotlin.Unit.a
        L57:
            return r1
        L58:
            java.lang.Object r6 = r0.c
            kotlin.jvm.internal.J r6 = (kotlin.jvm.internal.J) r6
            r6.a = r5
            kotlinx.coroutines.flow.internal.AbortFlowException r5 = new kotlinx.coroutines.flow.internal.AbortFlowException
            r5.<init>(r0)
            throw r5
        L64:
            java.lang.Number r5 = (java.lang.Number) r5
            int r5 = r5.intValue()
            java.lang.Object r5 = r4.a(r5, r6)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.l0.emit(java.lang.Object, kotlin.coroutines.h):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public l0(Function2 function2, kotlin.jvm.internal.J j) {
        this.b = (kotlin.coroutines.jvm.internal.i) function2;
        this.c = j;
    }
}
