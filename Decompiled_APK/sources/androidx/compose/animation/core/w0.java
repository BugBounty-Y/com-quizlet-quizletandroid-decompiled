package androidx.compose.animation.core;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class w0 {
    public final L0 a;
    public final InterfaceC0773a0 b = C0776c.z(null);
    public final /* synthetic */ E0 c;

    public w0(E0 e0, L0 l0, String str) {
        this.c = e0;
        this.a = l0;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final C0272v0 a(Function1 function1, Function1 function12) {
        InterfaceC0773a0 interfaceC0773a0 = this.b;
        C0272v0 c0272v0 = (C0272v0) ((androidx.compose.runtime.L0) interfaceC0773a0).getValue();
        E0 e0 = this.c;
        if (c0272v0 == null) {
            Object objInvoke = function12.invoke(e0.a.t());
            Object objInvoke2 = function12.invoke(e0.a.t());
            L0 l0 = this.a;
            AbstractC0267t abstractC0267t = (AbstractC0267t) l0.a.invoke(objInvoke2);
            abstractC0267t.d();
            z0 z0Var = new z0(e0, objInvoke, abstractC0267t, l0);
            c0272v0 = new C0272v0(this, z0Var, function1, function12);
            ((androidx.compose.runtime.L0) interfaceC0773a0).setValue(c0272v0);
            e0.i.add(z0Var);
        }
        c0272v0.c = (kotlin.jvm.internal.r) function12;
        c0272v0.b = (kotlin.jvm.internal.r) function1;
        c0272v0.a(e0.f());
        return c0272v0;
    }
}
