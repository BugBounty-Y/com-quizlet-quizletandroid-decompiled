package kotlinx.collections.immutable.implementations.persistentOrderedMap;

import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements Iterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a;
    public final f b;

    public e(d map, int i) {
        this.a = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(map, "map");
                this.b = new f(map.b, map);
                break;
            case 2:
                Intrinsics.checkNotNullParameter(map, "map");
                this.b = new f(map.b, map);
                break;
            default:
                Intrinsics.checkNotNullParameter(map, "map");
                this.b = new f(map.b, map);
                break;
        }
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
        }
        return this.b.hasNext();
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                f fVar = this.b;
                return new kotlinx.collections.immutable.implementations.immutableMap.a(fVar.b.d, fVar.c, fVar.next());
            case 1:
                f fVar2 = this.b;
                fVar2.next();
                return fVar2.c;
            default:
                return this.b.next().a;
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                this.b.remove();
                break;
            case 1:
                this.b.remove();
                break;
            default:
                this.b.remove();
                break;
        }
    }
}
