package grading.core;

import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class f {
    public static final Set a;
    public static final Set b;
    public static final Set c;

    static {
        String[] elements = {"de", "chem", "math"};
        Intrinsics.checkNotNullParameter(elements, "elements");
        a = C4933y.T(elements);
        String[] elements2 = {"chem", "math"};
        Intrinsics.checkNotNullParameter(elements2, "elements");
        Set setT = C4933y.T(elements2);
        b = setT;
        String[] elements3 = {"photo", "??"};
        Intrinsics.checkNotNullParameter(elements3, "elements");
        LinkedHashSet linkedHashSetB0 = CollectionsKt.B0(setT, C4933y.T(elements3));
        String[] elements4 = {"akk", "ja", "ja-ka", "zh-CN", "zh-TW"};
        Intrinsics.checkNotNullParameter(elements4, "elements");
        CollectionsKt.B0(linkedHashSetB0, C4933y.T(elements4));
        String[] elements5 = {"ja", "ja-ka", "zh-CN", "zh-TW"};
        Intrinsics.checkNotNullParameter(elements5, "elements");
        c = C4933y.T(elements5);
    }
}
