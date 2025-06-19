package kotlinx.collections.immutable.implementations.persistentOrderedMap;

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
                a a = (a) obj;
                a b2 = (a) obj2;
                Intrinsics.checkNotNullParameter(a, "a");
                Intrinsics.checkNotNullParameter(b2, "b");
                return Boolean.valueOf(Intrinsics.b(a.a, b2.a));
            case 1:
                a a2 = (a) obj;
                a b3 = (a) obj2;
                Intrinsics.checkNotNullParameter(a2, "a");
                Intrinsics.checkNotNullParameter(b3, "b");
                return Boolean.valueOf(Intrinsics.b(a2.a, b3.a));
            case 2:
                a a3 = (a) obj;
                Intrinsics.checkNotNullParameter(a3, "a");
                return Boolean.valueOf(Intrinsics.b(a3.a, obj2));
            case 3:
                a a4 = (a) obj;
                Intrinsics.checkNotNullParameter(a4, "a");
                return Boolean.valueOf(Intrinsics.b(a4.a, obj2));
            case 4:
                a a5 = (a) obj;
                a b4 = (a) obj2;
                Intrinsics.checkNotNullParameter(a5, "a");
                Intrinsics.checkNotNullParameter(b4, "b");
                return Boolean.valueOf(Intrinsics.b(a5.a, b4.a));
            case 5:
                a a6 = (a) obj;
                a b5 = (a) obj2;
                Intrinsics.checkNotNullParameter(a6, "a");
                Intrinsics.checkNotNullParameter(b5, "b");
                return Boolean.valueOf(Intrinsics.b(a6.a, b5.a));
            case 6:
                a a7 = (a) obj;
                Intrinsics.checkNotNullParameter(a7, "a");
                return Boolean.valueOf(Intrinsics.b(a7.a, obj2));
            default:
                a a8 = (a) obj;
                Intrinsics.checkNotNullParameter(a8, "a");
                return Boolean.valueOf(Intrinsics.b(a8.a, obj2));
        }
    }
}
