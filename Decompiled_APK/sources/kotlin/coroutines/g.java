package kotlin.coroutines;

import androidx.compose.animation.d0;
import java.io.Serializable;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.H;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements CoroutineContext, Serializable {
    public final CoroutineContext a;
    public final CoroutineContext.Element b;

    public g(CoroutineContext left, CoroutineContext.Element element) {
        Intrinsics.checkNotNullParameter(left, "left");
        Intrinsics.checkNotNullParameter(element, "element");
        this.a = left;
        this.b = element;
    }

    private final Object writeReplace() {
        int iB = b();
        CoroutineContext[] coroutineContextArr = new CoroutineContext[iB];
        H h = new H();
        fold(Unit.a, new f(coroutineContextArr, h));
        if (h.a == iB) {
            return new d(coroutineContextArr);
        }
        throw new IllegalStateException("Check failed.");
    }

    public final int b() {
        int i = 2;
        g gVar = this;
        while (true) {
            CoroutineContext coroutineContext = gVar.a;
            gVar = coroutineContext instanceof g ? (g) coroutineContext : null;
            if (gVar == null) {
                return i;
            }
            i++;
        }
    }

    public final boolean equals(Object obj) {
        boolean zB;
        if (this == obj) {
            return true;
        }
        if (obj instanceof g) {
            g gVar = (g) obj;
            if (gVar.b() == b()) {
                g gVar2 = this;
                while (true) {
                    CoroutineContext.Element element = gVar2.b;
                    if (!Intrinsics.b(gVar.get(element.getKey()), element)) {
                        zB = false;
                        break;
                    }
                    CoroutineContext coroutineContext = gVar2.a;
                    if (!(coroutineContext instanceof g)) {
                        Intrinsics.e(coroutineContext, "null cannot be cast to non-null type kotlin.coroutines.CoroutineContext.Element");
                        CoroutineContext.Element element2 = (CoroutineContext.Element) coroutineContext;
                        zB = Intrinsics.b(gVar.get(element2.getKey()), element2);
                        break;
                    }
                    gVar2 = (g) coroutineContext;
                }
                if (zB) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final Object fold(Object obj, Function2 operation) {
        Intrinsics.checkNotNullParameter(operation, "operation");
        return operation.invoke(this.a.fold(obj, operation), this.b);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext.Element get(l key) {
        Intrinsics.checkNotNullParameter(key, "key");
        g gVar = this;
        while (true) {
            CoroutineContext.Element element = gVar.b.get(key);
            if (element != null) {
                return element;
            }
            CoroutineContext coroutineContext = gVar.a;
            if (!(coroutineContext instanceof g)) {
                return coroutineContext.get(key);
            }
            gVar = (g) coroutineContext;
        }
    }

    public final int hashCode() {
        return this.b.hashCode() + this.a.hashCode();
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext minusKey(l key) {
        Intrinsics.checkNotNullParameter(key, "key");
        CoroutineContext.Element element = this.b;
        CoroutineContext.Element element2 = element.get(key);
        CoroutineContext coroutineContext = this.a;
        if (element2 != null) {
            return coroutineContext;
        }
        CoroutineContext coroutineContextMinusKey = coroutineContext.minusKey(key);
        return coroutineContextMinusKey == coroutineContext ? this : coroutineContextMinusKey == n.a ? element : new g(coroutineContextMinusKey, element);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext plus(CoroutineContext context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return context == n.a ? this : (CoroutineContext) context.fold(this, m.a);
    }

    public final String toString() {
        return d0.r(new StringBuilder("["), (String) fold("", e.a), ']');
    }
}
