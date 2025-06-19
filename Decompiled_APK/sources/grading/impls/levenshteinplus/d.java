package grading.impls.levenshteinplus;

import grading.core.g;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class d extends C4956o implements Function1 {
    public static final d a = new d(1, e.class, "removeEnglishArticles", "removeEnglishArticles(Ljava/lang/String;)Ljava/lang/String;", 1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String p0 = (String) obj;
        Intrinsics.checkNotNullParameter(p0, "p0");
        grading.core.a aVar = e.a;
        Intrinsics.checkNotNullParameter(p0, "<this>");
        return g.i.replace(p0, "");
    }
}
