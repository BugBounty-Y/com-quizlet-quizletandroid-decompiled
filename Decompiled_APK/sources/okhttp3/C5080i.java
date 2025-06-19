package okhttp3;

import java.util.Comparator;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: okhttp3.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5080i implements Comparator {
    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        String a = (String) obj;
        String b = (String) obj2;
        Intrinsics.checkNotNullParameter(a, "a");
        Intrinsics.checkNotNullParameter(b, "b");
        int iMin = Math.min(a.length(), b.length());
        for (int i = 4; i < iMin; i++) {
            char cCharAt = a.charAt(i);
            char cCharAt2 = b.charAt(i);
            if (cCharAt != cCharAt2) {
                return Intrinsics.g(cCharAt, cCharAt2) < 0 ? -1 : 1;
            }
        }
        int length = a.length();
        int length2 = b.length();
        if (length != length2) {
            return length < length2 ? -1 : 1;
        }
        return 0;
    }
}
