package androidx.compose.foundation.text.selection;

import androidx.collection.AbstractC0217o;
import androidx.compose.animation.C0281h;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicLong;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b0 implements Z {
    public static final com.quizlet.data.repository.explanations.myexplanations.a l;
    public boolean a;
    public final ArrayList b = new ArrayList();
    public final androidx.collection.z c;
    public final AtomicLong d;
    public C0541w e;
    public androidx.compose.foundation.lazy.f f;
    public P g;
    public C0540v h;
    public C0541w i;
    public C0541w j;
    public final InterfaceC0773a0 k;

    static {
        a0 a0Var = a0.a;
        K k = K.d;
        com.quizlet.data.repository.explanations.myexplanations.a aVar = androidx.compose.runtime.saveable.m.a;
        l = new com.quizlet.data.repository.explanations.myexplanations.a(a0Var, false, k, 3);
    }

    public b0(long j) {
        androidx.collection.z zVar = AbstractC0217o.a;
        this.c = new androidx.collection.z();
        this.d = new AtomicLong(j);
        androidx.collection.z zVar2 = AbstractC0217o.a;
        Intrinsics.e(zVar2, "null cannot be cast to non-null type androidx.collection.LongObjectMap<V of androidx.collection.LongObjectMapKt.emptyLongObjectMap>");
        this.k = C0776c.z(zVar2);
    }

    public final androidx.collection.z a() {
        return (androidx.collection.z) ((L0) this.k).getValue();
    }

    public final boolean b(androidx.compose.ui.layout.r rVar, long j, long j2, r rVar2, boolean z) {
        P p = this.g;
        if (p == null) {
            return true;
        }
        U u = p.a;
        long jA = U.a(u, rVar, j);
        long jA2 = U.a(u, rVar, j2);
        u.l(z);
        return u.p(jA, jA2, false, rVar2);
    }

    public final ArrayList c(androidx.compose.ui.layout.r rVar) {
        boolean z = this.a;
        ArrayList arrayList = this.b;
        if (!z) {
            kotlin.collections.F.t(arrayList, new androidx.camera.core.internal.compat.workaround.a(new C0281h(rVar, 13), 1));
            this.a = true;
        }
        return arrayList;
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x007c, code lost:
    
        if (((r8 & ((~r8) << 6)) & (-9187201950435737472L)) == 0) goto L22;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x007e, code lost:
    
        r14 = -1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(androidx.compose.foundation.text.selection.C0532m r19) {
        /*
            Method dump skipped, instructions count: 194
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.b0.d(androidx.compose.foundation.text.selection.m):void");
    }
}
