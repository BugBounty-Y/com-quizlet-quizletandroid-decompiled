package kotlin.collections;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.io.Serializable;
import java.util.AbstractCollection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.NoSuchElementException;
import java.util.RandomAccess;
import java.util.Set;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

@Metadata
/* loaded from: classes3.dex */
public final class CollectionsKt extends CollectionsKt___CollectionsKt {
    private CollectionsKt() {
    }

    public static Set A0(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        if (!(iterable instanceof Collection)) {
            LinkedHashSet linkedHashSet = new LinkedHashSet();
            s0(iterable, linkedHashSet);
            Intrinsics.checkNotNullParameter(linkedHashSet, "<this>");
            int size = linkedHashSet.size();
            return size != 0 ? size != 1 ? linkedHashSet : Z.b(linkedHashSet.iterator().next()) : M.a;
        }
        Collection collection = (Collection) iterable;
        int size2 = collection.size();
        if (size2 == 0) {
            return M.a;
        }
        if (size2 == 1) {
            return Z.b(iterable instanceof List ? ((List) iterable).get(0) : iterable.iterator().next());
        }
        LinkedHashSet linkedHashSet2 = new LinkedHashSet(U.a(collection.size()));
        s0(iterable, linkedHashSet2);
        return linkedHashSet2;
    }

    public static LinkedHashSet B0(Iterable iterable, Iterable other) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        LinkedHashSet linkedHashSetZ0 = z0(iterable);
        G.u(linkedHashSetZ0, other);
        return linkedHashSetZ0;
    }

    public static ArrayList C0(Iterable iterable, ArrayList other) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Intrinsics.checkNotNullParameter(other, "other");
        Iterator it2 = iterable.iterator();
        Iterator it3 = other.iterator();
        ArrayList arrayList = new ArrayList(Math.min(C.q(iterable, 10), C.q(other, 10)));
        while (it2.hasNext() && it3.hasNext()) {
            arrayList.add(new Pair(it2.next(), it3.next()));
        }
        return arrayList;
    }

    public static C4931w D(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        return new C4931w(iterable, 1);
    }

    public static ArrayList E(Iterable iterable, int i) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        if (i <= 0 || i <= 0) {
            throw new IllegalArgumentException(AbstractC0147y.c(i, "size ", " must be greater than zero.").toString());
        }
        if (!(iterable instanceof RandomAccess) || !(iterable instanceof List)) {
            ArrayList arrayList = new ArrayList();
            Iterator iterator = iterable.iterator();
            Intrinsics.checkNotNullParameter(iterator, "iterator");
            Iterator itA = !iterator.hasNext() ? J.a : kotlin.sequences.j.a(new c0(i, i, iterator, null));
            while (itA.hasNext()) {
                arrayList.add((List) itA.next());
            }
            return arrayList;
        }
        List list = (List) iterable;
        int size = list.size();
        ArrayList arrayList2 = new ArrayList((size / i) + (size % i == 0 ? 0 : 1));
        int i2 = 0;
        while (i2 >= 0 && i2 < size) {
            int i3 = size - i2;
            if (i <= i3) {
                i3 = i;
            }
            ArrayList arrayList3 = new ArrayList(i3);
            for (int i4 = 0; i4 < i3; i4++) {
                arrayList3.add(list.get(i4 + i2));
            }
            arrayList2.add(arrayList3);
            i2 += i;
        }
        return arrayList2;
    }

    public static boolean F(Iterable iterable, Object obj) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        return iterable instanceof Collection ? ((Collection) iterable).contains(obj) : P(iterable, obj) >= 0;
    }

    public static List G(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        return w0(z0(iterable));
    }

    public static List H(int i, List list) {
        ArrayList arrayList;
        Intrinsics.checkNotNullParameter(list, "<this>");
        if (i < 0) {
            throw new IllegalArgumentException(AbstractC0147y.c(i, "Requested element count ", " is less than zero.").toString());
        }
        if (i == 0) {
            return w0(list);
        }
        if (list != null) {
            int size = list.size() - i;
            if (size <= 0) {
                return K.a;
            }
            if (size == 1) {
                return A.b(T(list));
            }
            arrayList = new ArrayList(size);
            if (list != null) {
                if (list instanceof RandomAccess) {
                    int size2 = list.size();
                    while (i < size2) {
                        arrayList.add(list.get(i));
                        i++;
                    }
                } else {
                    ListIterator listIterator = list.listIterator(i);
                    while (listIterator.hasNext()) {
                        arrayList.add(listIterator.next());
                    }
                }
                return arrayList;
            }
        } else {
            arrayList = new ArrayList();
        }
        int i2 = 0;
        for (Object obj : list) {
            if (i2 >= i) {
                arrayList.add(obj);
            } else {
                i2++;
            }
        }
        return B.l(arrayList);
    }

    public static List I(int i, List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        if (i < 0) {
            throw new IllegalArgumentException(AbstractC0147y.c(i, "Requested element count ", " is less than zero.").toString());
        }
        int size = list.size() - i;
        if (size < 0) {
            size = 0;
        }
        return p0(list, size);
    }

    public static ArrayList J(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        ArrayList destination = new ArrayList();
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Intrinsics.checkNotNullParameter(destination, "destination");
        for (Object obj : iterable) {
            if (obj != null) {
                destination.add(obj);
            }
        }
        return destination;
    }

    public static Object K(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        if (iterable instanceof List) {
            return L((List) iterable);
        }
        Iterator it2 = iterable.iterator();
        if (it2.hasNext()) {
            return it2.next();
        }
        throw new NoSuchElementException("Collection is empty.");
    }

    public static Object L(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        if (list.isEmpty()) {
            throw new NoSuchElementException("List is empty.");
        }
        return list.get(0);
    }

    public static Object M(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        if (iterable instanceof List) {
            List list = (List) iterable;
            if (list.isEmpty()) {
                return null;
            }
            return list.get(0);
        }
        Iterator it2 = iterable.iterator();
        if (it2.hasNext()) {
            return it2.next();
        }
        return null;
    }

    public static Object N(Iterable iterable, Function1 predicate) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Intrinsics.checkNotNullParameter(predicate, "predicate");
        for (Object obj : iterable) {
            if (((Boolean) predicate.invoke(obj)).booleanValue()) {
                return obj;
            }
        }
        return null;
    }

    public static Object O(int i, List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        if (i < 0 || i >= list.size()) {
            return null;
        }
        return list.get(i);
    }

    public static int P(Iterable iterable, Object obj) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        if (iterable instanceof List) {
            return ((List) iterable).indexOf(obj);
        }
        int i = 0;
        for (Object obj2 : iterable) {
            if (i < 0) {
                B.p();
                throw null;
            }
            if (Intrinsics.b(obj, obj2)) {
                return i;
            }
            i++;
        }
        return -1;
    }

    public static LinkedHashSet Q(Iterable iterable, Iterable elements) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Intrinsics.checkNotNullParameter(elements, "other");
        LinkedHashSet linkedHashSetZ0 = z0(iterable);
        Intrinsics.checkNotNullParameter(linkedHashSetZ0, "<this>");
        Intrinsics.checkNotNullParameter(elements, "elements");
        linkedHashSetZ0.retainAll(G.w(elements));
        return linkedHashSetZ0;
    }

    public static /* synthetic */ void R(List list, StringBuilder sb, String str, Function1 function1, int i) {
        if ((i & 64) != 0) {
            function1 = null;
        }
        CollectionsKt___CollectionsKt.B(list, sb, str, "", "", function1);
    }

    public static String S(Iterable iterable, CharSequence charSequence, String str, String str2, Function1 function1, int i) {
        if ((i & 1) != 0) {
            charSequence = ", ";
        }
        CharSequence separator = charSequence;
        String prefix = (i & 2) != 0 ? "" : str;
        String postfix = (i & 4) != 0 ? "" : str2;
        if ((i & 32) != 0) {
            function1 = null;
        }
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Intrinsics.checkNotNullParameter(separator, "separator");
        Intrinsics.checkNotNullParameter(prefix, "prefix");
        Intrinsics.checkNotNullParameter(postfix, "postfix");
        Intrinsics.checkNotNullParameter("...", "truncated");
        StringBuilder sb = new StringBuilder();
        CollectionsKt___CollectionsKt.B(iterable, sb, separator, prefix, postfix, function1);
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public static Object T(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        if (iterable instanceof List) {
            return U((List) iterable);
        }
        Iterator it2 = iterable.iterator();
        if (!it2.hasNext()) {
            throw new NoSuchElementException("Collection is empty.");
        }
        Object next = it2.next();
        while (it2.hasNext()) {
            next = it2.next();
        }
        return next;
    }

    public static Object U(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        if (list.isEmpty()) {
            throw new NoSuchElementException("List is empty.");
        }
        return list.get(B.i(list));
    }

    public static Object V(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        if (list.isEmpty()) {
            return null;
        }
        return list.get(list.size() - 1);
    }

    public static Comparable W(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Iterator it2 = iterable.iterator();
        if (!it2.hasNext()) {
            return null;
        }
        Comparable comparable = (Comparable) it2.next();
        while (it2.hasNext()) {
            Comparable comparable2 = (Comparable) it2.next();
            if (comparable.compareTo(comparable2) < 0) {
                comparable = comparable2;
            }
        }
        return comparable;
    }

    public static Float X(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Iterator it2 = iterable.iterator();
        if (!it2.hasNext()) {
            return null;
        }
        float fFloatValue = ((Number) it2.next()).floatValue();
        while (it2.hasNext()) {
            fFloatValue = Math.max(fFloatValue, ((Number) it2.next()).floatValue());
        }
        return Float.valueOf(fFloatValue);
    }

    public static Comparable Y(ArrayList arrayList) {
        Intrinsics.checkNotNullParameter(arrayList, "<this>");
        Iterator it2 = arrayList.iterator();
        if (!it2.hasNext()) {
            return null;
        }
        Comparable comparable = (Comparable) it2.next();
        while (it2.hasNext()) {
            Comparable comparable2 = (Comparable) it2.next();
            if (comparable.compareTo(comparable2) > 0) {
                comparable = comparable2;
            }
        }
        return comparable;
    }

    public static Float Z(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Iterator it2 = iterable.iterator();
        if (!it2.hasNext()) {
            return null;
        }
        float fFloatValue = ((Number) it2.next()).floatValue();
        while (it2.hasNext()) {
            fFloatValue = Math.min(fFloatValue, ((Number) it2.next()).floatValue());
        }
        return Float.valueOf(fFloatValue);
    }

    public static ArrayList a0(Iterable iterable, Serializable serializable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        ArrayList arrayList = new ArrayList(C.q(iterable, 10));
        boolean z = false;
        for (Object obj : iterable) {
            boolean z2 = true;
            if (!z && Intrinsics.b(obj, serializable)) {
                z = true;
                z2 = false;
            }
            if (z2) {
                arrayList.add(obj);
            }
        }
        return arrayList;
    }

    public static List b0(Iterable iterable, Iterable elements) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Intrinsics.checkNotNullParameter(elements, "elements");
        Collection collectionW = G.w(elements);
        if (collectionW.isEmpty()) {
            return w0(iterable);
        }
        ArrayList arrayList = new ArrayList();
        for (Object obj : iterable) {
            if (!collectionW.contains(obj)) {
                arrayList.add(obj);
            }
        }
        return arrayList;
    }

    public static ArrayList c0(Collection collection, Iterable elements) {
        Intrinsics.checkNotNullParameter(collection, "<this>");
        Intrinsics.checkNotNullParameter(elements, "elements");
        if (!(elements instanceof Collection)) {
            ArrayList arrayList = new ArrayList(collection);
            G.u(arrayList, elements);
            return arrayList;
        }
        Collection collection2 = (Collection) elements;
        ArrayList arrayList2 = new ArrayList(collection2.size() + collection.size());
        arrayList2.addAll(collection);
        arrayList2.addAll(collection2);
        return arrayList2;
    }

    public static ArrayList d0(Collection collection, Object obj) {
        Intrinsics.checkNotNullParameter(collection, "<this>");
        ArrayList arrayList = new ArrayList(collection.size() + 1);
        arrayList.addAll(collection);
        arrayList.add(obj);
        return arrayList;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static ArrayList e0(kotlin.ranges.e eVar, kotlin.ranges.e elements) {
        Intrinsics.checkNotNullParameter(eVar, "<this>");
        Intrinsics.checkNotNullParameter(elements, "elements");
        if (eVar instanceof Collection) {
            return c0((Collection) eVar, elements);
        }
        ArrayList arrayList = new ArrayList();
        G.u(arrayList, eVar);
        G.u(arrayList, elements);
        return arrayList;
    }

    public static Object f0(List list, kotlin.random.e random) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        Intrinsics.checkNotNullParameter(random, "random");
        if (list.isEmpty()) {
            throw new NoSuchElementException("Collection is empty.");
        }
        int iD = random.d(list.size());
        Intrinsics.checkNotNullParameter(list, "<this>");
        return list.get(iD);
    }

    public static List g0(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        if ((iterable instanceof Collection) && ((Collection) iterable).size() <= 1) {
            return w0(iterable);
        }
        List listC = CollectionsKt___CollectionsKt.C(iterable);
        Intrinsics.checkNotNullParameter(listC, "<this>");
        Collections.reverse(listC);
        return listC;
    }

    public static void h0(List list, kotlin.random.e random) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        Intrinsics.checkNotNullParameter(random, "random");
        for (int i = B.i(list); i > 0; i--) {
            int iD = random.d(i + 1);
            list.set(iD, list.set(i, list.get(iD)));
        }
    }

    public static Object i0(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        if (iterable instanceof List) {
            return j0((List) iterable);
        }
        Iterator it2 = iterable.iterator();
        if (!it2.hasNext()) {
            throw new NoSuchElementException("Collection is empty.");
        }
        Object next = it2.next();
        if (it2.hasNext()) {
            throw new IllegalArgumentException("Collection has more than one element.");
        }
        return next;
    }

    public static Object j0(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        int size = list.size();
        if (size == 0) {
            throw new NoSuchElementException("List is empty.");
        }
        if (size == 1) {
            return list.get(0);
        }
        throw new IllegalArgumentException("List has more than one element.");
    }

    public static Object k0(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        if (list.size() == 1) {
            return list.get(0);
        }
        return null;
    }

    public static List l0(List list, IntRange indices) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        Intrinsics.checkNotNullParameter(indices, "indices");
        if (indices.isEmpty()) {
            return K.a;
        }
        return w0(list.subList(indices.a, indices.b + 1));
    }

    public static List m0(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        if (list == null) {
            List listC = CollectionsKt___CollectionsKt.C(list);
            F.s(listC);
            return listC;
        }
        if (list.size() <= 1) {
            return w0(list);
        }
        Object[] array = list.toArray(new Comparable[0]);
        Comparable[] comparableArr = (Comparable[]) array;
        Intrinsics.checkNotNullParameter(comparableArr, "<this>");
        if (comparableArr.length > 1) {
            Arrays.sort(comparableArr);
        }
        return C4930v.c(array);
    }

    public static List n0(Iterable iterable, Comparator comparator) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Intrinsics.checkNotNullParameter(comparator, "comparator");
        if (!(iterable instanceof Collection)) {
            List listC = CollectionsKt___CollectionsKt.C(iterable);
            F.t(listC, comparator);
            return listC;
        }
        Collection collection = (Collection) iterable;
        if (collection.size() <= 1) {
            return w0(iterable);
        }
        Object[] array = collection.toArray(new Object[0]);
        C4930v.t(array, comparator);
        return C4930v.c(array);
    }

    public static int o0(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Iterator it2 = iterable.iterator();
        int iIntValue = 0;
        while (it2.hasNext()) {
            iIntValue += ((Number) it2.next()).intValue();
        }
        return iIntValue;
    }

    public static List p0(Iterable iterable, int i) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        if (i < 0) {
            throw new IllegalArgumentException(AbstractC0147y.c(i, "Requested element count ", " is less than zero.").toString());
        }
        if (i == 0) {
            return K.a;
        }
        if (iterable instanceof Collection) {
            if (i >= ((Collection) iterable).size()) {
                return w0(iterable);
            }
            if (i == 1) {
                return A.b(K(iterable));
            }
        }
        ArrayList arrayList = new ArrayList(i);
        Iterator it2 = iterable.iterator();
        int i2 = 0;
        while (it2.hasNext()) {
            arrayList.add(it2.next());
            i2++;
            if (i2 == i) {
                break;
            }
        }
        return B.l(arrayList);
    }

    public static List q0(int i, List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        if (i < 0) {
            throw new IllegalArgumentException(AbstractC0147y.c(i, "Requested element count ", " is less than zero.").toString());
        }
        if (i == 0) {
            return K.a;
        }
        int size = list.size();
        if (i >= size) {
            return w0(list);
        }
        if (i == 1) {
            return A.b(U(list));
        }
        ArrayList arrayList = new ArrayList(i);
        if (list instanceof RandomAccess) {
            for (int i2 = size - i; i2 < size; i2++) {
                arrayList.add(list.get(i2));
            }
        } else {
            ListIterator listIterator = list.listIterator(size - i);
            while (listIterator.hasNext()) {
                arrayList.add(listIterator.next());
            }
        }
        return arrayList;
    }

    public static boolean[] r0(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        boolean[] zArr = new boolean[list.size()];
        Iterator it2 = list.iterator();
        int i = 0;
        while (it2.hasNext()) {
            zArr[i] = ((Boolean) it2.next()).booleanValue();
            i++;
        }
        return zArr;
    }

    public static void s0(Iterable iterable, AbstractCollection destination) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        Intrinsics.checkNotNullParameter(destination, "destination");
        Iterator it2 = iterable.iterator();
        while (it2.hasNext()) {
            destination.add(it2.next());
        }
    }

    public static float[] t0(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        float[] fArr = new float[list.size()];
        Iterator it2 = list.iterator();
        int i = 0;
        while (it2.hasNext()) {
            fArr[i] = ((Number) it2.next()).floatValue();
            i++;
        }
        return fArr;
    }

    public static HashSet u0(ArrayList arrayList) {
        Intrinsics.checkNotNullParameter(arrayList, "<this>");
        HashSet hashSet = new HashSet(U.a(C.q(arrayList, 12)));
        s0(arrayList, hashSet);
        return hashSet;
    }

    public static int[] v0(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        int[] iArr = new int[list.size()];
        Iterator it2 = list.iterator();
        int i = 0;
        while (it2.hasNext()) {
            iArr[i] = ((Number) it2.next()).intValue();
            i++;
        }
        return iArr;
    }

    public static List w0(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        if (!(iterable instanceof Collection)) {
            return B.l(CollectionsKt___CollectionsKt.C(iterable));
        }
        Collection collection = (Collection) iterable;
        int size = collection.size();
        if (size == 0) {
            return K.a;
        }
        if (size != 1) {
            return y0(collection);
        }
        return A.b(iterable instanceof List ? ((List) iterable).get(0) : iterable.iterator().next());
    }

    public static long[] x0(Collection collection) {
        Intrinsics.checkNotNullParameter(collection, "<this>");
        long[] jArr = new long[collection.size()];
        Iterator it2 = collection.iterator();
        int i = 0;
        while (it2.hasNext()) {
            jArr[i] = ((Number) it2.next()).longValue();
            i++;
        }
        return jArr;
    }

    public static ArrayList y0(Collection collection) {
        Intrinsics.checkNotNullParameter(collection, "<this>");
        return new ArrayList(collection);
    }

    public static LinkedHashSet z0(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        if (iterable instanceof Collection) {
            return new LinkedHashSet((Collection) iterable);
        }
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        s0(iterable, linkedHashSet);
        return linkedHashSet;
    }
}
