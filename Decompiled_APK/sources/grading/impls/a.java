package grading.impls;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a extends C4956o implements Function1 {
    public static final a a = new a(1, util.b.class, "normalizeSimilarCharacters", "normalizeSimilarCharacters(Ljava/lang/String;)Ljava/lang/String;", 1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String p0 = (String) obj;
        Intrinsics.checkNotNullParameter(p0, "p0");
        return util.b.a(p0);
    }
}
