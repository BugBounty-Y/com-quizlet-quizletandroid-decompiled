package util;

import java.util.ArrayList;
import kotlin.Pair;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class b {
    public static final Object a = V.f(new Pair((char) 8217, "'"), new Pair((char) 8217, "'"), new Pair((char) 8216, "'"), new Pair((char) 180, "'"), new Pair((char) 8221, "\""), new Pair((char) 8220, "\""), new Pair((char) 8230, "..."), new Pair('\t', " "), new Pair((char) 8194, " "), new Pair((char) 0, ""), new Pair((char) 8211, "-"), new Pair((char) 173, ""), new Pair((char) 12305, "] "), new Pair((char) 12304, " ["), new Pair((char) 215, "x"), new Pair((char) 537, "ş"), new Pair((char) 339, "oe"), new Pair((char) 230, "ae"), new Pair((char) 198, "AE"), new Pair((char) 1072, "a"), new Pair((char) 1040, "A"), new Pair((char) 1077, "e"), new Pair((char) 1045, "E"), new Pair((char) 1089, "c"), new Pair((char) 1057, "C"), new Pair((char) 1091, "y"), new Pair((char) 1059, "Y"), new Pair((char) 12288, " "), new Pair((char) 12289, ","), new Pair((char) 12290, "."), new Pair((char) 12316, "~"), new Pair((char) 65292, ", "), new Pair((char) 65294, ". "), new Pair((char) 65281, "! "), new Pair((char) 65311, "? "), new Pair((char) 65307, "; "), new Pair((char) 65306, ": "), new Pair((char) 65288, " ("), new Pair((char) 65289, ") "), new Pair((char) 65374, "~ "));

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v1, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r1v2 */
    /* JADX WARN: Type inference failed for: r1v3, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r1v4, types: [java.lang.Object, java.util.ArrayList] */
    public static final String a(String str) {
        Iterable destination;
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(str, "<this>");
        int length = str.length();
        if (length != 0) {
            if (length != 1) {
                Intrinsics.checkNotNullParameter(str, "<this>");
                destination = new ArrayList(str.length());
                Intrinsics.checkNotNullParameter(str, "<this>");
                Intrinsics.checkNotNullParameter(destination, "destination");
                for (int i = 0; i < str.length(); i++) {
                    destination.add(Character.valueOf(str.charAt(i)));
                }
            } else {
                destination = A.b(Character.valueOf(str.charAt(0)));
            }
        } else {
            destination = K.a;
        }
        return CollectionsKt.S(destination, "", null, null, a.b, 30);
    }
}
