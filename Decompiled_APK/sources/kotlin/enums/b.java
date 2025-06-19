package kotlin.enums;

import java.io.Serializable;
import kotlin.collections.AbstractC4916g;
import kotlin.collections.C4913d;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends AbstractC4916g implements a, Serializable {
    public final Enum[] b;

    public b(Enum[] entries) {
        Intrinsics.checkNotNullParameter(entries, "entries");
        this.b = entries;
    }

    private final Object writeReplace() {
        return new d(this.b);
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.b.length;
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        if (!(obj instanceof Enum)) {
            return false;
        }
        Enum element = (Enum) obj;
        Intrinsics.checkNotNullParameter(element, "element");
        return ((Enum) C4933y.F(element.ordinal(), this.b)) == element;
    }

    @Override // java.util.List
    public final Object get(int i) {
        C4913d c4913d = AbstractC4916g.a;
        Enum[] enumArr = this.b;
        int length = enumArr.length;
        c4913d.getClass();
        C4913d.b(i, length);
        return enumArr[i];
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final int indexOf(Object obj) {
        if (!(obj instanceof Enum)) {
            return -1;
        }
        Enum element = (Enum) obj;
        Intrinsics.checkNotNullParameter(element, "element");
        int iOrdinal = element.ordinal();
        if (((Enum) C4933y.F(iOrdinal, this.b)) == element) {
            return iOrdinal;
        }
        return -1;
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final int lastIndexOf(Object obj) {
        if (!(obj instanceof Enum)) {
            return -1;
        }
        Enum element = (Enum) obj;
        Intrinsics.checkNotNullParameter(element, "element");
        return indexOf(element);
    }
}
