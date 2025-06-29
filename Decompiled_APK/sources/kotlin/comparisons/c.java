package kotlin.comparisons;

import java.util.Comparator;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class c implements Comparator {

    @NotNull
    public static final c a = new c();

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        Comparable a2 = (Comparable) obj;
        Comparable b = (Comparable) obj2;
        Intrinsics.checkNotNullParameter(a2, "a");
        Intrinsics.checkNotNullParameter(b, "b");
        return b.compareTo(a2);
    }

    @Override // java.util.Comparator
    public final Comparator reversed() {
        return b.a;
    }
}
