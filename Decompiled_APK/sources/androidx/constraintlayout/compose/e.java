package androidx.constraintlayout.compose;

import androidx.compose.ui.layout.InterfaceC0899u;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e implements InterfaceC0899u {
    public final b a;
    public final Function1 b;
    public final Object c;

    public e(b bVar, Function1 function1) {
        this.a = bVar;
        this.b = function1;
        this.c = bVar.b;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a.b, eVar.a.b) && this.b == eVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.b.hashCode() * 31);
    }

    @Override // androidx.compose.ui.layout.InterfaceC0899u
    public final Object t() {
        return this.c;
    }
}
