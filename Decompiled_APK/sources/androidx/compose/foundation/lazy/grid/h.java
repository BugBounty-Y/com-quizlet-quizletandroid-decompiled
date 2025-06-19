package androidx.compose.foundation.lazy.grid;

import kotlin.Pair;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ h(int i, Function1 function1) {
        super(2);
        this.a = i;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                return new C0427b(((C0427b) this.b.invoke((v) obj)).a);
            default:
                String answer = (String) obj;
                String test2 = (String) obj2;
                Intrinsics.checkNotNullParameter(answer, "answer");
                Intrinsics.checkNotNullParameter(test2, "test");
                Function1 function1 = this.b;
                return new Pair(function1.invoke(answer), function1.invoke(test2));
        }
    }
}
