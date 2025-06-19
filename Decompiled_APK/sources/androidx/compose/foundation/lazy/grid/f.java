package androidx.compose.foundation.lazy.grid;

import androidx.compose.foundation.lazy.layout.InterfaceC0447t;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class f implements InterfaceC0447t {
    public final Function1 a;
    public final Function2 b;
    public final Function1 c;
    public final androidx.compose.runtime.internal.d d;

    public f(Function1 function1, Function2 function2, Function1 function12, androidx.compose.runtime.internal.d dVar) {
        this.a = function1;
        this.b = function2;
        this.c = function12;
        this.d = dVar;
    }

    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0447t
    public final Function1 getKey() {
        return this.a;
    }

    @Override // androidx.compose.foundation.lazy.layout.InterfaceC0447t
    public final Function1 getType() {
        return this.c;
    }
}
