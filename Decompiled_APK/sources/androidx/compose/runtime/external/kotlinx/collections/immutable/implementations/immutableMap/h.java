package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h implements Iterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a = 0;
    public final Object b;

    public h(Enumeration enumeration) {
        this.b = enumeration;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                return ((f) this.b).c;
            case 1:
                return ((Enumeration) this.b).hasMoreElements();
            default:
                return ((kotlinx.collections.immutable.implementations.immutableMap.e) this.b).c;
        }
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                return (Map.Entry) ((f) this.b).next();
            case 1:
                return ((Enumeration) this.b).nextElement();
            default:
                return (Map.Entry) ((kotlinx.collections.immutable.implementations.immutableMap.e) this.b).next();
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                ((f) this.b).remove();
                return;
            case 1:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            default:
                ((kotlinx.collections.immutable.implementations.immutableMap.e) this.b).remove();
                return;
        }
    }

    public h(e eVar) {
        o[] oVarArr = new o[8];
        for (int i = 0; i < 8; i++) {
            oVarArr[i] = new q(this);
        }
        this.b = new f(eVar, oVarArr);
    }

    public h(kotlinx.collections.immutable.implementations.immutableMap.d builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        o[] oVarArr = new o[8];
        for (int i = 0; i < 8; i++) {
            oVarArr[i] = new kotlinx.collections.immutable.implementations.immutableMap.l(this);
        }
        this.b = new kotlinx.collections.immutable.implementations.immutableMap.e(builder, oVarArr);
    }
}
