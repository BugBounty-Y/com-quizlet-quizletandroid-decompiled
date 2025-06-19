package kotlin.coroutines;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class m extends r implements Function2 {
    public static final m a = new m(2);

    public m() {
        super(2);
    }

    @Override // kotlin.jvm.functions.Function2
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final CoroutineContext invoke(CoroutineContext acc, CoroutineContext.Element element) {
        Intrinsics.checkNotNullParameter(acc, "acc");
        Intrinsics.checkNotNullParameter(element, "element");
        CoroutineContext coroutineContextMinusKey = acc.minusKey(element.getKey());
        n nVar = n.a;
        if (coroutineContextMinusKey == nVar) {
            return element;
        }
        i iVar = j.a1;
        j jVar = (j) coroutineContextMinusKey.get(iVar);
        if (jVar == null) {
            return new g(coroutineContextMinusKey, element);
        }
        CoroutineContext coroutineContextMinusKey2 = coroutineContextMinusKey.minusKey(iVar);
        return coroutineContextMinusKey2 == nVar ? new g(element, jVar) : new g(new g(coroutineContextMinusKey2, element), jVar);
    }
}
