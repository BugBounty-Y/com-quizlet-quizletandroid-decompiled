package kotlin;

import java.io.Serializable;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u implements k, Serializable {
    public Function0 a;
    public volatile Object b;
    public final Object c;

    public u(Function0 initializer, Object obj, int i, DefaultConstructorMarker defaultConstructorMarker) {
        obj = (i & 2) != 0 ? null : obj;
        Intrinsics.checkNotNullParameter(initializer, "initializer");
        this.a = initializer;
        this.b = F.a;
        this.c = obj == null ? this : obj;
    }

    private final Object writeReplace() {
        return new C4939h(getValue());
    }

    @Override // kotlin.k
    public final Object getValue() {
        Object objInvoke;
        Object obj = this.b;
        F f = F.a;
        if (obj != f) {
            return obj;
        }
        synchronized (this.c) {
            objInvoke = this.b;
            if (objInvoke == f) {
                Function0 function0 = this.a;
                Intrinsics.d(function0);
                objInvoke = function0.invoke();
                this.b = objInvoke;
                this.a = null;
            }
        }
        return objInvoke;
    }

    @Override // kotlin.k
    public final boolean isInitialized() {
        return this.b != F.a;
    }

    public final String toString() {
        return isInitialized() ? String.valueOf(getValue()) : "Lazy value not initialized yet.";
    }
}
