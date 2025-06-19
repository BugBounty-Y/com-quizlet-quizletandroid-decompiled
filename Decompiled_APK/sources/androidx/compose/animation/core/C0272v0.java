package androidx.compose.animation.core;

import androidx.compose.runtime.W0;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.animation.core.v0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0272v0 implements W0 {
    public final z0 a;
    public kotlin.jvm.internal.r b;
    public kotlin.jvm.internal.r c;
    public final /* synthetic */ w0 d;

    /* JADX WARN: Multi-variable type inference failed */
    public C0272v0(w0 w0Var, z0 z0Var, Function1 function1, Function1 function12) {
        this.d = w0Var;
        this.a = z0Var;
        this.b = (kotlin.jvm.internal.r) function1;
        this.c = (kotlin.jvm.internal.r) function12;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r1v4, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r1v5, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r3v1, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    public final void a(x0 x0Var) {
        Object objInvoke = this.c.invoke(x0Var.c());
        boolean zH = this.d.c.h();
        z0 z0Var = this.a;
        if (zH) {
            z0Var.h(this.c.invoke(x0Var.a()), objInvoke, (D) this.b.invoke(x0Var));
        } else {
            z0Var.i(objInvoke, (D) this.b.invoke(x0Var));
        }
    }

    @Override // androidx.compose.runtime.W0
    public final Object getValue() {
        a(this.d.c.f());
        return ((androidx.compose.runtime.L0) this.a.j).getValue();
    }
}
