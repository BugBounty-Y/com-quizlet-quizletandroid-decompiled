package kotlin.text;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class x extends u {
    public static String b(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter("  ", "indent");
        return kotlin.sequences.q.g(kotlin.sequences.q.h(StringsKt__StringsKt.v(str), new w(1)), "\n");
    }

    public static String c(String str) {
        int length;
        String strA;
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter("", "newIndent");
        List listR = StringsKt.R(str);
        ArrayList arrayList = new ArrayList();
        for (Object obj : listR) {
            if (!StringsKt.O((String) obj)) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (true) {
            length = 0;
            if (!it2.hasNext()) {
                break;
            }
            String str2 = (String) it2.next();
            int length2 = str2.length();
            while (true) {
                if (length >= length2) {
                    length = -1;
                    break;
                }
                if (!CharsKt.b(str2.charAt(length))) {
                    break;
                }
                length++;
            }
            if (length == -1) {
                length = str2.length();
            }
            arrayList2.add(Integer.valueOf(length));
        }
        Integer num = (Integer) CollectionsKt.Y(arrayList2);
        int iIntValue = num != null ? num.intValue() : 0;
        int length3 = str.length();
        listR.size();
        v vVar = v.a;
        int i = kotlin.collections.B.i(listR);
        ArrayList arrayList3 = new ArrayList();
        Iterator it3 = listR.iterator();
        while (true) {
            String strA2 = null;
            if (!it3.hasNext()) {
                StringBuilder sb = new StringBuilder(length3);
                CollectionsKt.R(arrayList3, sb, "\n", null, 124);
                String string = sb.toString();
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                return string;
            }
            Object next = it3.next();
            int i2 = length + 1;
            if (length < 0) {
                kotlin.collections.B.p();
                throw null;
            }
            String str3 = (String) next;
            if (((length != 0 && length != i) || !StringsKt.O(str3)) && ((strA = I.A(iIntValue, str3)) == null || (strA2 = vVar.invoke(strA)) == null)) {
                strA2 = str3;
            }
            if (strA2 != null) {
                arrayList3.add(strA2);
            }
            length = i2;
        }
    }

    public static String d(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter("|", "marginPrefix");
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter("", "newIndent");
        Intrinsics.checkNotNullParameter("|", "marginPrefix");
        if (StringsKt.O("|")) {
            throw new IllegalArgumentException("marginPrefix must be non-blank string.");
        }
        List listR = StringsKt.R(str);
        int length = str.length();
        listR.size();
        v vVar = v.a;
        int i = kotlin.collections.B.i(listR);
        ArrayList arrayList = new ArrayList();
        Iterator it2 = listR.iterator();
        int i2 = 0;
        while (true) {
            String strA = null;
            if (!it2.hasNext()) {
                StringBuilder sb = new StringBuilder(length);
                CollectionsKt.R(arrayList, sb, "\n", null, 124);
                String string = sb.toString();
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                return string;
            }
            Object next = it2.next();
            int i3 = i2 + 1;
            if (i2 < 0) {
                kotlin.collections.B.p();
                throw null;
            }
            String str2 = (String) next;
            if ((i2 != 0 && i2 != i) || !StringsKt.O(str2)) {
                int length2 = str2.length();
                int i4 = 0;
                while (true) {
                    if (i4 >= length2) {
                        i4 = -1;
                        break;
                    }
                    if (!CharsKt.b(str2.charAt(i4))) {
                        break;
                    }
                    i4++;
                }
                if (i4 != -1 && D.q(str2, i4, "|", false)) {
                    strA = str2.substring("|".length() + i4);
                    Intrinsics.checkNotNullExpressionValue(strA, "substring(...)");
                }
                if (strA == null || (strA = vVar.invoke(strA)) == null) {
                    strA = str2;
                }
            }
            if (strA != null) {
                arrayList.add(strA);
            }
            i2 = i3;
        }
    }
}
