package assistantMode.utils;

import assistantMode.enums.m;
import assistantMode.types.G;
import assistantMode.types.unions.ImageAttribute;
import java.util.Locale;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public abstract class c {
    public static final Regex a = new Regex("[\\p{L}0-9]");

    public static final String a(G term, m cardSide, Map diagramShapesByTermId) {
        String str;
        ImageAttribute imageAttribute;
        String str2;
        Intrinsics.checkNotNullParameter(term, "term");
        Intrinsics.checkNotNullParameter(cardSide, "cardSide");
        Intrinsics.checkNotNullParameter(diagramShapesByTermId, "diagramShapesByTermId");
        if (cardSide == m.d) {
            assistantMode.types.h hVar = (assistantMode.types.h) diagramShapesByTermId.get(Long.valueOf(term.a));
            if (hVar != null && (str2 = hVar.b) != null) {
                return Integer.valueOf(str2.hashCode()).toString();
            }
        } else {
            Intrinsics.checkNotNullParameter(term, "<this>");
            Intrinsics.checkNotNullParameter(cardSide, "cardSide");
            int iOrdinal = cardSide.ordinal();
            if (iOrdinal == 0) {
                str = term.b;
            } else {
                if (iOrdinal != 1) {
                    throw new IllegalStateException("Unrecognized textual card side: " + cardSide);
                }
                str = term.g;
            }
            String lowerCase = StringsKt.g0(str).toString().toLowerCase(Locale.ROOT);
            Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
            Intrinsics.checkNotNullParameter(term, "<this>");
            Intrinsics.checkNotNullParameter(cardSide, "cardSide");
            String str3 = (cardSide != m.c || (imageAttribute = term.l) == null) ? null : imageAttribute.a;
            if ((lowerCase.length() > 0 && a.a(lowerCase)) || str3 != null) {
                if (str3 == null) {
                    str3 = "";
                }
                return lowerCase + "/_/_/" + str3.hashCode();
            }
        }
        return null;
    }
}
