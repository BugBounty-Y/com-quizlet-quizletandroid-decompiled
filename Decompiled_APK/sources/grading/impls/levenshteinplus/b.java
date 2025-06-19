package grading.impls.levenshteinplus;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.text.MatchResult;

/* loaded from: classes3.dex */
public final class b extends r implements Function1 {
    public static final b b = new b(1, 0);
    public static final b c = new b(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                MatchResult it2 = (MatchResult) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return it2.getValue();
            default:
                MatchResult it3 = (MatchResult) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return it3.getValue();
        }
    }
}
