package kotlinx.coroutines;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.coroutines.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4978d implements InterfaceC5024j {
    public final C4976c[] a;

    public C4978d(C4976c[] c4976cArr) {
        this.a = c4976cArr;
    }

    public final void a() {
        for (C4976c c4976c : this.a) {
            Q q = c4976c.f;
            if (q == null) {
                Intrinsics.m("handle");
                throw null;
            }
            q.dispose();
        }
    }

    @Override // kotlinx.coroutines.InterfaceC5024j
    public final void b(Throwable th) {
        a();
    }

    public final String toString() {
        return "DisposeHandlersOnCancel[" + this.a + ']';
    }
}
