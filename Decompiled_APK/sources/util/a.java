package util;

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

    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, java.util.Map] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                Character ch = (Character) obj;
                char cCharValue = ch.charValue();
                String str = (String) b.a.get(ch);
                return str != null ? str : String.valueOf(cCharValue);
            default:
                MatchResult result = (MatchResult) obj;
                Intrinsics.checkNotNullParameter(result, "result");
                return (CharSequence) result.b().get(1);
        }
    }
}
