package kotlin.text;

import java.util.regex.Pattern;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n {
    public n(DefaultConstructorMarker defaultConstructorMarker) {
    }

    public static String a(String literal) {
        Intrinsics.checkNotNullParameter(literal, "literal");
        String strQuote = Pattern.quote(literal);
        Intrinsics.checkNotNullExpressionValue(strQuote, "quote(...)");
        return strQuote;
    }
}
