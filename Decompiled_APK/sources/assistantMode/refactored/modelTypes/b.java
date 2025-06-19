package assistantMode.refactored.modelTypes;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public final CardSide a;

    public b(CardSide cardSide) {
        Intrinsics.checkNotNullParameter(cardSide, "cardSide");
        this.a = cardSide;
    }

    public final ArrayList a() {
        List list = this.a.d;
        if (list == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList.add(new a((CardSideDistractor) it2.next()));
        }
        return arrayList;
    }

    public final AudioValue b() {
        Object next;
        Iterator it2 = this.a.c.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (((c) next) instanceof AudioValue) {
                break;
            }
        }
        if (next instanceof AudioValue) {
            return (AudioValue) next;
        }
        return null;
    }

    public final TextValue c() {
        Object next;
        Iterator it2 = this.a.c.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (((c) next) instanceof TextValue) {
                break;
            }
        }
        if (next instanceof TextValue) {
            return (TextValue) next;
        }
        return null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "AnnotatedCardSideShim(cardSide=" + this.a + ")";
    }
}
