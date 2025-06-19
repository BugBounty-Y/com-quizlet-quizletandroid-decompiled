package androidx.compose.foundation.pager;

import androidx.compose.foundation.lazy.layout.InterfaceC0447t;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class o implements InterfaceC0447t {
    public final Function1 a;
    public final kotlin.jvm.functions.d b;

    public o(Function1 function1, kotlin.jvm.functions.d dVar) {
        this.a = function1;
        this.b = dVar;
    }

    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0447t
    public final Function1 getKey() {
        return this.a;
    }
}
