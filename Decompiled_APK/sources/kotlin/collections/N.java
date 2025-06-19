package kotlin.collections;

import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.C4963b;
import kotlin.text.C4964c;
import kotlinx.serialization.internal.C5070y;

/* loaded from: classes3.dex */
public final class N implements Iterable, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ N(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                return new O(((C4932x) this.b).invoke());
            case 1:
                return new C4963b((C4964c) this.b);
            default:
                return new androidx.collection.Y((C5070y) this.b);
        }
    }

    public N(C4932x iteratorFactory) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(iteratorFactory, "iteratorFactory");
        this.b = iteratorFactory;
    }
}
