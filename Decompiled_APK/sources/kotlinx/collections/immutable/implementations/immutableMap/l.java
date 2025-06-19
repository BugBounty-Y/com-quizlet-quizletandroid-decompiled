package kotlinx.collections.immutable.implementations.immutableMap;

import androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l extends o {
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.h e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.h parentIterator) {
        super(1);
        Intrinsics.checkNotNullParameter(parentIterator, "parentIterator");
        this.e = parentIterator;
    }

    @Override // java.util.Iterator
    public final Object next() {
        int i = this.d;
        this.d = i + 2;
        Object[] objArr = this.b;
        return new a(this.e, objArr[i], objArr[i + 1]);
    }
}
