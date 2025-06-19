package androidx.compose.runtime;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class T implements InterfaceC0834w0 {
    public final Function2 a;
    public final kotlinx.coroutines.internal.d b;
    public kotlinx.coroutines.y0 c;

    public T(CoroutineContext coroutineContext, Function2 function2) {
        this.a = function2;
        this.b = kotlinx.coroutines.E.c(coroutineContext);
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void a() {
        kotlinx.coroutines.y0 y0Var = this.c;
        if (y0Var != null) {
            y0Var.z(new J(1));
        }
        this.c = null;
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void b() {
        kotlinx.coroutines.y0 y0Var = this.c;
        if (y0Var != null) {
            y0Var.z(new J(1));
        }
        this.c = null;
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void d() {
        kotlinx.coroutines.y0 y0Var = this.c;
        if (y0Var != null) {
            kotlinx.coroutines.E.j(y0Var, "Old job was still running!", null);
        }
        this.c = kotlinx.coroutines.E.A(this.b, null, null, this.a, 3);
    }
}
