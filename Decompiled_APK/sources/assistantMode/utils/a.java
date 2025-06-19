package assistantMode.utils;

import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;

/* loaded from: classes.dex */
public abstract class a {
    public static final Set a;

    static {
        String[] elements = {"en", "en-US", "en-GB", "es", "de", "fr"};
        Intrinsics.checkNotNullParameter(elements, "elements");
        a = C4933y.T(elements);
    }

    public static final boolean a(String str) {
        return (str.length() > 0 ? StringsKt__StringsKt.split$default(str, new String[]{" "}, false, 0, 6, null).size() : 0) >= 3;
    }
}
