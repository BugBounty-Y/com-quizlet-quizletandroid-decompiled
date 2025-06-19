package androidx.lifecycle;

import kotlin.InterfaceC4938g;
import kotlin.jvm.internal.InterfaceC4953l;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class v0 implements Z, InterfaceC4953l {
    public final /* synthetic */ u0 a;

    public v0(u0 function) {
        Intrinsics.checkNotNullParameter(function, "function");
        this.a = function;
    }

    @Override // androidx.lifecycle.Z
    public final /* synthetic */ void a(Object obj) {
        this.a.invoke(obj);
    }

    public final boolean equals(Object obj) {
        if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
            return Intrinsics.b(getFunctionDelegate(), ((InterfaceC4953l) obj).getFunctionDelegate());
        }
        return false;
    }

    @Override // kotlin.jvm.internal.InterfaceC4953l
    public final InterfaceC4938g getFunctionDelegate() {
        return this.a;
    }

    public final int hashCode() {
        return getFunctionDelegate().hashCode();
    }
}
