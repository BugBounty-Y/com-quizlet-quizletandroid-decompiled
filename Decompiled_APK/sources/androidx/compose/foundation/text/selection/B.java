package androidx.compose.foundation.text.selection;

import androidx.appcompat.widget.C0122z;
import androidx.compose.foundation.text.u0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class B extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ InterfaceC0530k m;
    public final /* synthetic */ C0122z n;
    public final /* synthetic */ u0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(InterfaceC0530k interfaceC0530k, C0122z c0122z, u0 u0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = interfaceC0530k;
        this.n = c0122z;
        this.o = u0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        B b = new B(this.m, this.n, this.o, hVar);
        b.l = obj;
        return b;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((B) create((androidx.compose.ui.input.pointer.z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x006b, code lost:
    
        if (androidx.compose.foundation.text.selection.W.j(r1, r9.m, r9.n, r10, r9) == r0) goto L32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x007e, code lost:
    
        if (androidx.compose.foundation.text.selection.W.k(r1, r9.o, r10, r9) == r0) goto L32;
     */
    /* JADX WARN: Type inference failed for: r2v6, types: [java.lang.Object, java.util.List] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r10) {
        /*
            r9 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r9.k
            r2 = 1
            r3 = 3
            r4 = 2
            if (r1 == 0) goto L24
            if (r1 == r2) goto L1c
            if (r1 == r4) goto L18
            if (r1 != r3) goto L10
            goto L18
        L10:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L18:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L81
        L1c:
            java.lang.Object r1 = r9.l
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L37
        L24:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.lang.Object r10 = r9.l
            r1 = r10
            androidx.compose.ui.input.pointer.z r1 = (androidx.compose.ui.input.pointer.z) r1
            r9.l = r1
            r9.k = r2
            java.lang.Object r10 = androidx.compose.foundation.text.selection.W.i(r1, r9)
            if (r10 != r0) goto L37
            goto L80
        L37:
            androidx.compose.ui.input.pointer.f r10 = (androidx.compose.ui.input.pointer.f) r10
            boolean r2 = androidx.compose.foundation.text.selection.W.v(r10)
            r5 = 0
            if (r2 == 0) goto L6e
            int r2 = r10.c
            r2 = r2 & 33
            if (r2 == 0) goto L6e
            java.lang.Object r2 = r10.a
            int r6 = r2.size()
            r7 = 0
        L4d:
            if (r7 >= r6) goto L5f
            java.lang.Object r8 = r2.get(r7)
            androidx.compose.ui.input.pointer.n r8 = (androidx.compose.ui.input.pointer.n) r8
            boolean r8 = r8.b()
            if (r8 == 0) goto L5c
            goto L6e
        L5c:
            int r7 = r7 + 1
            goto L4d
        L5f:
            r9.l = r5
            r9.k = r4
            androidx.appcompat.widget.z r2 = r9.n
            androidx.compose.foundation.text.selection.k r3 = r9.m
            java.lang.Object r10 = androidx.compose.foundation.text.selection.W.j(r1, r3, r2, r10, r9)
            if (r10 != r0) goto L81
            goto L80
        L6e:
            boolean r2 = androidx.compose.foundation.text.selection.W.v(r10)
            if (r2 != 0) goto L81
            r9.l = r5
            r9.k = r3
            androidx.compose.foundation.text.u0 r2 = r9.o
            java.lang.Object r10 = androidx.compose.foundation.text.selection.W.k(r1, r2, r10, r9)
            if (r10 != r0) goto L81
        L80:
            return r0
        L81:
            kotlin.Unit r10 = kotlin.Unit.a
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.B.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
