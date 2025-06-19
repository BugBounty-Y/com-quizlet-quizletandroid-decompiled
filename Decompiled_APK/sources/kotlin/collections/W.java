package kotlin.collections;

import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* loaded from: classes3.dex */
public final class W extends AbstractC4916g {
    public final /* synthetic */ int b = 0;
    public final Object c;

    public W(List delegate) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.c = delegate;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        switch (this.b) {
            case 0:
                return ((List) this.c).size();
            default:
                return ((kotlin.text.m) this.c).a.groupCount() + 1;
        }
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public /* bridge */ boolean contains(Object obj) {
        switch (this.b) {
            case 1:
                if (obj instanceof String) {
                    return super.contains((String) obj);
                }
                return false;
            default:
                return super.contains(obj);
        }
    }

    @Override // java.util.List
    public final Object get(int i) {
        switch (this.b) {
            case 0:
                if (i >= 0 && i <= B.i(this)) {
                    return ((List) this.c).get(B.i(this) - i);
                }
                StringBuilder sbV = android.support.v4.media.session.a.v(i, "Element index ", " must be in range [");
                sbV.append(new IntRange(0, B.i(this), 1));
                sbV.append("].");
                throw new IndexOutOfBoundsException(sbV.toString());
            default:
                String strGroup = ((kotlin.text.m) this.c).a.group(i);
                return strGroup == null ? "" : strGroup;
        }
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public /* bridge */ int indexOf(Object obj) {
        switch (this.b) {
            case 1:
                if (obj instanceof String) {
                    return super.indexOf((String) obj);
                }
                return -1;
            default:
                return super.indexOf(obj);
        }
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.Collection, java.lang.Iterable, java.util.List
    public Iterator iterator() {
        switch (this.b) {
            case 0:
                return new androidx.compose.runtime.snapshots.C(this, 0);
            default:
                return super.iterator();
        }
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public /* bridge */ int lastIndexOf(Object obj) {
        switch (this.b) {
            case 1:
                if (obj instanceof String) {
                    return super.lastIndexOf((String) obj);
                }
                return -1;
            default:
                return super.lastIndexOf(obj);
        }
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public ListIterator listIterator() {
        switch (this.b) {
            case 0:
                return new androidx.compose.runtime.snapshots.C(this, 0);
            default:
                return super.listIterator();
        }
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public ListIterator listIterator(int i) {
        switch (this.b) {
            case 0:
                return new androidx.compose.runtime.snapshots.C(this, i);
            default:
                return super.listIterator(i);
        }
    }

    public W(kotlin.text.m mVar) {
        this.c = mVar;
    }
}
