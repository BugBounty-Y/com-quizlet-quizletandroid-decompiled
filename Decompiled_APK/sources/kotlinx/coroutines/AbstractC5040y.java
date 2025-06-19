package kotlinx.coroutines;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: kotlinx.coroutines.y, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC5040y extends kotlin.coroutines.a implements kotlin.coroutines.j {
    public static final C5039x a = new C5039x(kotlin.coroutines.j.a1, new com.sdk.growthbook.utils.a(20));

    public AbstractC5040y() {
        super(kotlin.coroutines.j.a1);
    }

    public void B(CoroutineContext coroutineContext, Runnable runnable) {
        kotlinx.coroutines.internal.b.h(this, coroutineContext, runnable);
    }

    public boolean a0(CoroutineContext coroutineContext) {
        return !(this instanceof G0);
    }

    public AbstractC5040y c0(int i) {
        kotlinx.coroutines.internal.b.a(i);
        return new kotlinx.coroutines.internal.g(this, i);
    }

    @Override // kotlin.coroutines.a, kotlin.coroutines.CoroutineContext
    public final CoroutineContext.Element get(kotlin.coroutines.l key) {
        Intrinsics.checkNotNullParameter(key, "key");
        if (!(key instanceof kotlin.coroutines.b)) {
            if (kotlin.coroutines.j.a1 == key) {
                return this;
            }
            return null;
        }
        kotlin.coroutines.b bVar = (kotlin.coroutines.b) key;
        kotlin.coroutines.l key2 = getKey();
        bVar.getClass();
        Intrinsics.checkNotNullParameter(key2, "key");
        if (key2 != bVar && bVar.b != key2) {
            return null;
        }
        Intrinsics.checkNotNullParameter(this, "element");
        CoroutineContext.Element element = (CoroutineContext.Element) bVar.a.invoke(this);
        if (element != null) {
            return element;
        }
        return null;
    }

    @Override // kotlin.coroutines.a, kotlin.coroutines.CoroutineContext
    public final CoroutineContext minusKey(kotlin.coroutines.l key) {
        Intrinsics.checkNotNullParameter(key, "key");
        if (key instanceof kotlin.coroutines.b) {
            kotlin.coroutines.b bVar = (kotlin.coroutines.b) key;
            kotlin.coroutines.l key2 = getKey();
            bVar.getClass();
            Intrinsics.checkNotNullParameter(key2, "key");
            if (key2 != bVar && bVar.b != key2) {
                return this;
            }
            Intrinsics.checkNotNullParameter(this, "element");
            if (((CoroutineContext.Element) bVar.a.invoke(this)) != null) {
                return kotlin.coroutines.n.a;
            }
        } else if (kotlin.coroutines.j.a1 == key) {
            return kotlin.coroutines.n.a;
        }
        return this;
    }

    public abstract void r(CoroutineContext coroutineContext, Runnable runnable);

    public String toString() {
        return getClass().getSimpleName() + '@' + E.r(this);
    }
}
