package androidx.compose.runtime;

import kotlin.Pair;
import kotlin.collections.CollectionsKt;

/* renamed from: androidx.compose.runtime.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0816q implements InterfaceC0815p0 {
    public final /* synthetic */ C0833w a;
    public final /* synthetic */ Z b;

    public C0816q(C0833w c0833w, Z z) {
        this.a = c0833w;
        this.b = z;
    }

    @Override // androidx.compose.runtime.InterfaceC0815p0
    public final void a() {
    }

    /* JADX WARN: Type inference failed for: r1v2, types: [java.lang.Object, java.util.Collection] */
    @Override // androidx.compose.runtime.InterfaceC0815p0
    public final P b(C0813o0 c0813o0, Object obj) {
        P pB;
        C0833w c0833w = this.a;
        C0833w c0833w2 = c0833w instanceof InterfaceC0815p0 ? c0833w : null;
        if (c0833w2 == null || (pB = c0833w2.b(c0813o0, obj)) == null) {
            pB = P.a;
        }
        if (pB != P.a) {
            return pB;
        }
        Z z = this.b;
        z.f = CollectionsKt.d0(z.f, new Pair(c0813o0, obj));
        return P.b;
    }

    @Override // androidx.compose.runtime.InterfaceC0815p0
    public final void c(Object obj) {
    }
}
