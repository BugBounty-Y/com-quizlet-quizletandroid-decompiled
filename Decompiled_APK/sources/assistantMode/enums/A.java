package assistantMode.enums;

import java.util.LinkedHashMap;
import java.util.Locale;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class A {
    public static final LinkedHashMap a;

    static {
        E[] eArr = {E.b, E.c, E.d};
        int iA = U.a(3);
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (int i = 0; i < 3; i++) {
            E e = eArr[i];
            linkedHashMap.put(a(e.name()), Integer.valueOf((int) (1 << e.a)));
        }
        a = linkedHashMap;
    }

    public static final String a(String str) {
        if (str.length() <= 0) {
            return str;
        }
        StringBuilder sb = new StringBuilder();
        String strValueOf = String.valueOf(str.charAt(0));
        Intrinsics.e(strValueOf, "null cannot be cast to non-null type java.lang.String");
        String lowerCase = strValueOf.toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        sb.append((Object) lowerCase);
        String strSubstring = str.substring(1);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        sb.append(strSubstring);
        return sb.toString();
    }
}
