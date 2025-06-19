package assistantMode.refactored.types.flashcards;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class d extends r implements Function1 {
    public static final d b = new d(1, 0);
    public static final d c = new d(1, 1);
    public static final d d = new d(1, 2);
    public static final d e = new d(1, 3);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                assistantMode.refactored.interfaces.c it2 = (assistantMode.refactored.interfaces.c) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return Long.valueOf(it2.d());
            case 1:
                assistantMode.refactored.interfaces.c it3 = (assistantMode.refactored.interfaces.c) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return Long.valueOf(it3.a());
            case 2:
                assistantMode.refactored.interfaces.c it4 = (assistantMode.refactored.interfaces.c) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                return Long.valueOf(it4.d());
            default:
                assistantMode.refactored.interfaces.c it5 = (assistantMode.refactored.interfaces.c) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                return Long.valueOf(it5.a());
        }
    }
}
