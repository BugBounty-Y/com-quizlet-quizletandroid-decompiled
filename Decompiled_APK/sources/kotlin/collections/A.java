package kotlin.collections;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class A {
    public static kotlin.collections.builders.d a(kotlin.collections.builders.d builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        builder.j();
        builder.c = true;
        return builder.b > 0 ? builder : kotlin.collections.builders.d.e;
    }

    public static List b(Object obj) {
        List listSingletonList = Collections.singletonList(obj);
        Intrinsics.checkNotNullExpressionValue(listSingletonList, "singletonList(...)");
        return listSingletonList;
    }

    public static List c(Iterable iterable) {
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        List listC = CollectionsKt___CollectionsKt.C(iterable);
        Collections.shuffle(listC);
        return listC;
    }

    public static List d(ArrayList arrayList, Random random) {
        Intrinsics.checkNotNullParameter(arrayList, "<this>");
        Intrinsics.checkNotNullParameter(random, "random");
        List listC = CollectionsKt___CollectionsKt.C(arrayList);
        Collections.shuffle(listC, random);
        return listC;
    }

    public static void e(int i, Object[] array) {
        Intrinsics.checkNotNullParameter(array, "array");
        if (i < array.length) {
            array[i] = null;
        }
    }
}
