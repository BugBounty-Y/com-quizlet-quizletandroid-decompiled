package kotlin;

import java.io.Serializable;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class J implements k, Serializable {
    public Function0 a;
    public Object b;

    private final Object writeReplace() {
        return new C4939h(getValue());
    }

    @Override // kotlin.k
    public final Object getValue() {
        if (this.b == F.a) {
            Function0 function0 = this.a;
            Intrinsics.d(function0);
            this.b = function0.invoke();
            this.a = null;
        }
        return this.b;
    }

    @Override // kotlin.k
    public final boolean isInitialized() {
        return this.b != F.a;
    }

    public final String toString() {
        return isInitialized() ? String.valueOf(getValue()) : "Lazy value not initialized yet.";
    }
}
