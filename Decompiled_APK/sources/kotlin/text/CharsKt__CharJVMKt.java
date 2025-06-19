package kotlin.text;

import kotlin.Metadata;
import kotlin.ranges.IntRange;

/* JADX INFO: Access modifiers changed from: package-private */
@Metadata
/* loaded from: classes3.dex */
public class CharsKt__CharJVMKt {
    public static int checkRadix(int i) {
        if (2 <= i && i < 37) {
            return i;
        }
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "radix ", " was not in valid range ");
        sbV.append(new IntRange(2, 36, 1));
        throw new IllegalArgumentException(sbV.toString());
    }
}
