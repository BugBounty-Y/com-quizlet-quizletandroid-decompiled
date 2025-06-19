package kotlin;

import java.io.Serializable;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.jvm.functions.Function0;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class t implements k, Serializable {

    @NotNull
    public static final s c = new s(null);
    public static final AtomicReferenceFieldUpdater d = AtomicReferenceFieldUpdater.newUpdater(t.class, Object.class, "b");
    public volatile Function0 a;
    public volatile Object b;

    private final Object writeReplace() {
        return new C4939h(getValue());
    }

    @Override // kotlin.k
    public final Object getValue() {
        Object obj = this.b;
        F f = F.a;
        if (obj != f) {
            return obj;
        }
        Function0 function0 = this.a;
        if (function0 != null) {
            Object objInvoke = function0.invoke();
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = d;
            while (!atomicReferenceFieldUpdater.compareAndSet(this, f, objInvoke)) {
                if (atomicReferenceFieldUpdater.get(this) != f) {
                }
            }
            this.a = null;
            return objInvoke;
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
