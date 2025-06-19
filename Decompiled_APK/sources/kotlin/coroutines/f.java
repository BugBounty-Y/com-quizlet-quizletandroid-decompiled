package kotlin.coroutines;

import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.H;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class f extends r implements Function2 {
    public final /* synthetic */ CoroutineContext[] a;
    public final /* synthetic */ H b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(CoroutineContext[] coroutineContextArr, H h) {
        super(2);
        this.a = coroutineContextArr;
        this.b = h;
    }

    public final void a(Unit unit, CoroutineContext.Element element) {
        Intrinsics.checkNotNullParameter(unit, "<anonymous parameter 0>");
        Intrinsics.checkNotNullParameter(element, "element");
        H h = this.b;
        int i = h.a;
        h.a = i + 1;
        this.a[i] = element;
    }

    @Override // kotlin.jvm.functions.Function2
    public final /* bridge */ /* synthetic */ Object invoke(Object obj, Object obj2) {
        a((Unit) obj, (CoroutineContext.Element) obj2);
        return Unit.a;
    }
}
