package androidx.compose.runtime;

import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class F implements InterfaceC0834w0 {
    public final Function1 a;
    public G b;

    public F(Function1 function1) {
        this.a = function1;
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void a() {
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void b() {
        G g = this.b;
        if (g != null) {
            g.dispose();
        }
        this.b = null;
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void d() {
        this.b = (G) this.a.invoke(C0776c.b);
    }
}
