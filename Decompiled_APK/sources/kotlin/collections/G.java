package kotlin.collections;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.RandomAccess;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class G extends F {
    public static Object A(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        if (list.isEmpty()) {
            throw new NoSuchElementException("List is empty.");
        }
        return list.remove(B.i(list));
    }

    public static void u(Collection collection, Iterable elements) {
        Intrinsics.checkNotNullParameter(collection, "<this>");
        Intrinsics.checkNotNullParameter(elements, "elements");
        if (elements instanceof Collection) {
            collection.addAll((Collection) elements);
            return;
        }
        Iterator it2 = elements.iterator();
        while (it2.hasNext()) {
            collection.add(it2.next());
        }
    }

    public static void v(Collection collection, Object[] elements) {
        Intrinsics.checkNotNullParameter(collection, "<this>");
        Intrinsics.checkNotNullParameter(elements, "elements");
        collection.addAll(C4930v.c(elements));
    }

    public static final Collection w(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        return iterable instanceof Collection ? (Collection) iterable : CollectionsKt.w0(iterable);
    }

    public static final boolean x(Iterable iterable, Function1 function1, boolean z) {
        Iterator it2 = iterable.iterator();
        boolean z2 = false;
        while (it2.hasNext()) {
            if (((Boolean) function1.invoke(it2.next())).booleanValue() == z) {
                it2.remove();
                z2 = true;
            }
        }
        return z2;
    }

    public static boolean y(List list, Function1 predicate) {
        int i;
        Intrinsics.checkNotNullParameter(list, "<this>");
        Intrinsics.checkNotNullParameter(predicate, "predicate");
        if (!(list instanceof RandomAccess)) {
            Intrinsics.e(list, "null cannot be cast to non-null type kotlin.collections.MutableIterable<T of kotlin.collections.CollectionsKt__MutableCollectionsKt.filterInPlace>");
            if (!(list instanceof kotlin.jvm.internal.markers.a) || (list instanceof kotlin.jvm.internal.markers.b)) {
                return x(list, predicate, true);
            }
            kotlin.jvm.internal.O.g(list, "kotlin.collections.MutableIterable");
            throw null;
        }
        int i2 = B.i(list);
        if (i2 >= 0) {
            int i3 = 0;
            i = 0;
            while (true) {
                Object obj = list.get(i3);
                if (!((Boolean) predicate.invoke(obj)).booleanValue()) {
                    if (i != i3) {
                        list.set(i, obj);
                    }
                    i++;
                }
                if (i3 == i2) {
                    break;
                }
                i3++;
            }
        } else {
            i = 0;
        }
        if (i >= list.size()) {
            return false;
        }
        int i4 = B.i(list);
        if (i > i4) {
            return true;
        }
        while (true) {
            list.remove(i4);
            if (i4 == i) {
                return true;
            }
            i4--;
        }
    }

    public static Object z(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        if (list.isEmpty()) {
            throw new NoSuchElementException("List is empty.");
        }
        return list.remove(0);
    }
}
