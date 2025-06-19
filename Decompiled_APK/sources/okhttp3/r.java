package okhttp3;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;

/* loaded from: classes3.dex */
public final class r implements Iterable, kotlin.jvm.internal.markers.a {
    public final String[] a;

    public r(String[] strArr) {
        this.a = strArr;
    }

    public final String a(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        String[] strArr = this.a;
        int length = strArr.length - 2;
        int iA = kotlin.internal.c.a(length, 0, -2);
        if (iA > length) {
            return null;
        }
        while (!kotlin.text.D.l(name, strArr[length], true)) {
            if (length == iA) {
                return null;
            }
            length -= 2;
        }
        return strArr[length + 1];
    }

    public final String b(int i) {
        return this.a[i * 2];
    }

    public final com.android.billingclient.api.h e() {
        com.android.billingclient.api.h hVar = new com.android.billingclient.api.h(3);
        kotlin.collections.G.v(hVar.a, this.a);
        return hVar;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof r) {
            return Arrays.equals(this.a, ((r) obj).a);
        }
        return false;
    }

    public final String g(int i) {
        return this.a[(i * 2) + 1];
    }

    public final List h(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        int size = size();
        ArrayList arrayList = null;
        for (int i = 0; i < size; i++) {
            if (kotlin.text.D.l(name, b(i), true)) {
                if (arrayList == null) {
                    arrayList = new ArrayList(2);
                }
                arrayList.add(g(i));
            }
        }
        if (arrayList == null) {
            return kotlin.collections.K.a;
        }
        List listUnmodifiableList = Collections.unmodifiableList(arrayList);
        Intrinsics.checkNotNullExpressionValue(listUnmodifiableList, "{\n      Collections.unmodifiableList(result)\n    }");
        return listUnmodifiableList;
    }

    public final int hashCode() {
        return Arrays.hashCode(this.a);
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        int size = size();
        Pair[] pairArr = new Pair[size];
        for (int i = 0; i < size; i++) {
            pairArr[i] = new Pair(b(i), g(i));
        }
        return O.f(pairArr);
    }

    public final int size() {
        return this.a.length / 2;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        int size = size();
        for (int i = 0; i < size; i++) {
            String strB = b(i);
            String strG = g(i);
            sb.append(strB);
            sb.append(": ");
            if (okhttp3.internal.b.r(strB)) {
                strG = "██";
            }
            sb.append(strG);
            sb.append("\n");
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "StringBuilder().apply(builderAction).toString()");
        return string;
    }
}
