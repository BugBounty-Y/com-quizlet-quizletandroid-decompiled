package org.wordpress.aztec.source;

import java.util.regex.Pattern;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.text.MatchResult;

/* loaded from: classes3.dex */
public final class a extends r implements Function1 {
    public static final a b = new a(1, 0);
    public static final a c = new a(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                MatchResult matchResult = (MatchResult) obj;
                Intrinsics.checkNotNullParameter(matchResult, "matchResult");
                String strReplaceAll = Pattern.compile("(\\r\\n|\\n)").matcher((String) matchResult.b().get(0)).replaceAll("<wp-line-break>");
                Intrinsics.checkNotNullExpressionValue(strReplaceAll, "replaceAll(...)");
                return strReplaceAll;
            default:
                MatchResult matchResult2 = (MatchResult) obj;
                Intrinsics.checkNotNullParameter(matchResult2, "matchResult");
                String strReplaceAll2 = Pattern.compile("<br ?/?>(\\r\\n|\\n)?").matcher((String) matchResult2.b().get(0)).replaceAll("<wp-line-break>");
                Intrinsics.checkNotNullExpressionValue(strReplaceAll2, "replaceAll(...)");
                String strReplaceAll3 = Pattern.compile("</?p( [^>]*)?>(\\r\\n|\\n)?").matcher(strReplaceAll2).replaceAll("<wp-line-break>");
                Intrinsics.checkNotNullExpressionValue(strReplaceAll3, "replaceAll(...)");
                String strReplaceAll4 = Pattern.compile("\\r?\\n").matcher(strReplaceAll3).replaceAll("<wp-line-break>");
                Intrinsics.checkNotNullExpressionValue(strReplaceAll4, "replaceAll(...)");
                return strReplaceAll4;
        }
    }
}
