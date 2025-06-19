package kotlin.text;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class C extends B {
    public static Double e(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        try {
            if (t.b.e(str)) {
                return Double.valueOf(Double.parseDouble(str));
            }
        } catch (NumberFormatException unused) {
        }
        return null;
    }

    public static Float f(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        try {
            if (t.b.e(str)) {
                return Float.valueOf(Float.parseFloat(str));
            }
        } catch (NumberFormatException unused) {
        }
        return null;
    }
}
