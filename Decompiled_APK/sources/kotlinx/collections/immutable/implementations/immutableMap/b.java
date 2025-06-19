package kotlinx.collections.immutable.implementations.immutableMap;

import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements Function2 {
    public static final b b = new b(0);
    public static final b c = new b(1);
    public static final b d = new b(2);
    public static final b e = new b(3);
    public static final b f = new b(4);
    public static final b g = new b(5);
    public static final b h = new b(6);
    public static final b i = new b(7);
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i2) {
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                kotlinx.collections.immutable.implementations.persistentOrderedMap.a b2 = (kotlinx.collections.immutable.implementations.persistentOrderedMap.a) obj2;
                Intrinsics.checkNotNullParameter(b2, "b");
                return Boolean.valueOf(Intrinsics.b(obj, b2.a));
            case 1:
                kotlinx.collections.immutable.implementations.persistentOrderedMap.a b3 = (kotlinx.collections.immutable.implementations.persistentOrderedMap.a) obj2;
                Intrinsics.checkNotNullParameter(b3, "b");
                return Boolean.valueOf(Intrinsics.b(obj, b3.a));
            case 2:
                return Boolean.valueOf(Intrinsics.b(obj, obj2));
            case 3:
                return Boolean.valueOf(Intrinsics.b(obj, obj2));
            case 4:
                return Boolean.valueOf(Intrinsics.b(obj, obj2));
            case 5:
                return Boolean.valueOf(Intrinsics.b(obj, obj2));
            case 6:
                kotlinx.collections.immutable.implementations.persistentOrderedMap.a b4 = (kotlinx.collections.immutable.implementations.persistentOrderedMap.a) obj2;
                Intrinsics.checkNotNullParameter(b4, "b");
                return Boolean.valueOf(Intrinsics.b(obj, b4.a));
            default:
                kotlinx.collections.immutable.implementations.persistentOrderedMap.a b5 = (kotlinx.collections.immutable.implementations.persistentOrderedMap.a) obj2;
                Intrinsics.checkNotNullParameter(b5, "b");
                return Boolean.valueOf(Intrinsics.b(obj, b5.a));
        }
    }
}
