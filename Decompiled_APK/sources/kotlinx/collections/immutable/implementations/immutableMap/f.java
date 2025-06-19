package kotlinx.collections.immutable.implementations.immutableMap;

import java.util.Iterator;
import java.util.Map;
import kotlin.collections.AbstractC4922m;
import kotlin.collections.AbstractC4923n;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends AbstractC4923n {
    public final /* synthetic */ int a = 0;
    public final AbstractC4922m b;

    public f(d builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        this.b = builder;
    }

    @Override // kotlin.collections.AbstractC4923n
    public final int a() {
        switch (this.a) {
            case 0:
                return ((d) this.b).d();
            default:
                return ((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) this.b).d.d();
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean add(Object obj) {
        switch (this.a) {
            case 0:
                Map.Entry element = (Map.Entry) obj;
                Intrinsics.checkNotNullParameter(element, "element");
                throw new UnsupportedOperationException();
            default:
                Map.Entry element2 = (Map.Entry) obj;
                Intrinsics.checkNotNullParameter(element2, "element");
                throw new UnsupportedOperationException();
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final void clear() {
        switch (this.a) {
            case 0:
                ((d) this.b).clear();
                break;
            default:
                ((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) this.b).clear();
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x004e A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0050 A[RETURN, SYNTHETIC] */
    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean contains(java.lang.Object r4) {
        /*
            r3 = this;
            boolean r0 = r4 instanceof java.util.Map.Entry
            if (r0 != 0) goto L5
            goto L13
        L5:
            java.util.Map$Entry r4 = (java.util.Map.Entry) r4
            java.lang.String r0 = "element"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
            if (r4 == 0) goto L10
            r0 = r4
            goto L11
        L10:
            r0 = 0
        L11:
            if (r0 != 0) goto L15
        L13:
            r4 = 0
            return r4
        L15:
            int r0 = r3.a
            switch(r0) {
                case 0: goto L52;
                default: goto L1a;
            }
        L1a:
            java.lang.String r0 = "element"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
            java.lang.String r1 = "map"
            kotlin.collections.m r2 = r3.b
            kotlinx.collections.immutable.implementations.persistentOrderedMap.d r2 = (kotlinx.collections.immutable.implementations.persistentOrderedMap.d) r2
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r1)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
            java.lang.Object r0 = r4.getKey()
            java.lang.Object r0 = r2.get(r0)
            if (r0 == 0) goto L3e
            java.lang.Object r4 = r4.getValue()
            boolean r4 = r0.equals(r4)
            goto L87
        L3e:
            java.lang.Object r0 = r4.getValue()
            if (r0 != 0) goto L50
            java.lang.Object r4 = r4.getKey()
            boolean r4 = r2.containsKey(r4)
            if (r4 == 0) goto L50
        L4e:
            r4 = 1
            goto L87
        L50:
            r4 = 0
            goto L87
        L52:
            java.lang.String r0 = "element"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
            java.lang.String r1 = "map"
            kotlin.collections.m r2 = r3.b
            kotlinx.collections.immutable.implementations.immutableMap.d r2 = (kotlinx.collections.immutable.implementations.immutableMap.d) r2
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r1)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
            java.lang.Object r0 = r4.getKey()
            java.lang.Object r0 = r2.get(r0)
            if (r0 == 0) goto L76
            java.lang.Object r4 = r4.getValue()
            boolean r4 = r0.equals(r4)
            goto L87
        L76:
            java.lang.Object r0 = r4.getValue()
            if (r0 != 0) goto L50
            java.lang.Object r4 = r4.getKey()
            boolean r4 = r2.containsKey(r4)
            if (r4 == 0) goto L50
            goto L4e
        L87:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.collections.immutable.implementations.immutableMap.f.contains(java.lang.Object):boolean");
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                return new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.h((d) this.b);
            default:
                return new kotlinx.collections.immutable.implementations.persistentOrderedMap.e((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) this.b, 0);
        }
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean remove(Object obj) {
        if (!(obj instanceof Map.Entry)) {
            return false;
        }
        Map.Entry element = (Map.Entry) obj;
        Intrinsics.checkNotNullParameter(element, "element");
        if ((element != null ? element : null) == null) {
            return false;
        }
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(element, "element");
                return ((d) this.b).remove(element.getKey(), element.getValue());
            default:
                Intrinsics.checkNotNullParameter(element, "element");
                return ((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) this.b).remove(element.getKey(), element.getValue());
        }
    }

    public f(kotlinx.collections.immutable.implementations.persistentOrderedMap.d builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        this.b = builder;
    }
}
