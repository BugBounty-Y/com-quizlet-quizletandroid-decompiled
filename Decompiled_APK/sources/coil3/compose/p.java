package coil3.compose;

import androidx.compose.ui.layout.InterfaceC0901w;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.L;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.layout.W;
import kotlin.Unit;
import kotlin.collections.V;

/* loaded from: classes.dex */
public final class p implements coil3.size.i, InterfaceC0901w {
    public long b;
    public kotlin.coroutines.p c;

    @Override // androidx.compose.ui.layout.InterfaceC0901w
    public final L h(M m, J j, long j2) {
        n(j2);
        W wB = j.B(j2);
        return m.n0(wB.a, wB.b, V.c(), new n(wB, 0));
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x007d  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // coil3.size.i
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object l(kotlin.coroutines.h r7) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r7 instanceof coil3.compose.o
            if (r0 == 0) goto L13
            r0 = r7
            coil3.compose.o r0 = (coil3.compose.o) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L1a
        L13:
            coil3.compose.o r0 = new coil3.compose.o
            kotlin.coroutines.jvm.internal.c r7 = (kotlin.coroutines.jvm.internal.c) r7
            r0.<init>(r6, r7)
        L1a:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            kotlin.coroutines.p r1 = r0.k
            coil3.compose.p r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L63
        L2d:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            long r4 = r6.b
            boolean r7 = androidx.compose.ui.unit.a.k(r4)
            if (r7 == 0) goto L6d
            kotlin.coroutines.p r7 = r6.c
            r0.j = r6
            r0.k = r7
            r0.n = r3
            kotlin.coroutines.p r2 = new kotlin.coroutines.p
            kotlin.coroutines.h r3 = kotlin.coroutines.intrinsics.h.b(r0)
            r2.<init>(r3)
            r6.c = r2
            java.lang.Object r2 = r2.a()
            if (r2 != r1) goto L5e
            java.lang.String r3 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r3)
        L5e:
            if (r2 != r1) goto L61
            return r1
        L61:
            r0 = r6
            r1 = r7
        L63:
            if (r1 == 0) goto L6e
            kotlin.p r7 = kotlin.r.b
            kotlin.Unit r7 = kotlin.Unit.a
            r1.resumeWith(r7)
            goto L6e
        L6d:
            r0 = r6
        L6e:
            long r0 = r0.b
            coil3.size.h r7 = new coil3.size.h
            int r2 = androidx.compose.ui.unit.a.h(r0)
            coil3.size.b r3 = coil3.size.b.a
            r4 = 2147483647(0x7fffffff, float:NaN)
            if (r2 == r4) goto L86
            com.google.android.gms.internal.mlkit_vision_common.AbstractC3467i.a(r2)
            coil3.size.a r5 = new coil3.size.a
            r5.<init>(r2)
            goto L87
        L86:
            r5 = r3
        L87:
            int r0 = androidx.compose.ui.unit.a.g(r0)
            if (r0 == r4) goto L95
            com.google.android.gms.internal.mlkit_vision_common.AbstractC3467i.a(r0)
            coil3.size.a r3 = new coil3.size.a
            r3.<init>(r0)
        L95:
            r7.<init>(r5, r3)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: coil3.compose.p.l(kotlin.coroutines.h):java.lang.Object");
    }

    public final void n(long j) {
        this.b = j;
        if (androidx.compose.ui.unit.a.k(j)) {
            return;
        }
        kotlin.coroutines.p pVar = this.c;
        if (pVar != null) {
            kotlin.p pVar2 = kotlin.r.b;
            pVar.resumeWith(Unit.a);
        }
        this.c = null;
    }
}
