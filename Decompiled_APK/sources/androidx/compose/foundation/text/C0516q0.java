package androidx.compose.foundation.text;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.q0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0516q0 extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public androidx.compose.ui.input.pointer.n k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ u0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0516q0(u0 u0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = u0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0516q0 c0516q0 = new C0516q0(this.n, hVar);
        c0516q0.m = obj;
        return c0516q0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0516q0) create((androidx.compose.ui.input.pointer.z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0038, code lost:
    
        if (r13 == r0) goto L16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x0050, code lost:
    
        if (r13 != r0) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0052, code lost:
    
        return r0;
     */
    /* JADX WARN: Type inference failed for: r13v9, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:15:0x0050 -> B:17:0x0053). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.l
            r2 = 1
            r3 = 2
            androidx.compose.foundation.text.u0 r4 = r12.n
            if (r1 == 0) goto L28
            if (r1 == r2) goto L20
            if (r1 != r3) goto L18
            androidx.compose.ui.input.pointer.n r1 = r12.k
            java.lang.Object r2 = r12.m
            androidx.compose.ui.input.pointer.z r2 = (androidx.compose.ui.input.pointer.z) r2
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L53
        L18:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L20:
            java.lang.Object r1 = r12.m
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L3b
        L28:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            java.lang.Object r13 = r12.m
            r1 = r13
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            r12.m = r1
            r12.l = r2
            java.lang.Object r13 = androidx.compose.foundation.gestures.k1.c(r1, r12, r3)
            if (r13 != r0) goto L3b
            goto L52
        L3b:
            androidx.compose.ui.input.pointer.n r13 = (androidx.compose.ui.input.pointer.n) r13
            long r5 = r13.c
            r4.c()
            r2 = r1
            r1 = r13
        L44:
            r12.m = r2
            r12.k = r1
            r12.l = r3
            androidx.compose.ui.input.pointer.g r13 = androidx.compose.ui.input.pointer.g.b
            java.lang.Object r13 = r2.c(r13, r12)
            if (r13 != r0) goto L53
        L52:
            return r0
        L53:
            androidx.compose.ui.input.pointer.f r13 = (androidx.compose.ui.input.pointer.f) r13
            java.lang.Object r13 = r13.a
            int r5 = r13.size()
            r6 = 0
        L5c:
            if (r6 >= r5) goto L76
            java.lang.Object r7 = r13.get(r6)
            androidx.compose.ui.input.pointer.n r7 = (androidx.compose.ui.input.pointer.n) r7
            long r8 = r7.a
            long r10 = r1.a
            boolean r8 = androidx.compose.ui.input.pointer.m.a(r8, r10)
            if (r8 == 0) goto L73
            boolean r7 = r7.d
            if (r7 == 0) goto L73
            goto L44
        L73:
            int r6 = r6 + 1
            goto L5c
        L76:
            r4.b()
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.C0516q0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
