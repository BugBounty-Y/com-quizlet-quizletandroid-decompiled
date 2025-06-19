package androidx.compose.foundation.lazy.grid;

import java.util.List;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class o extends kotlin.jvm.internal.r implements Function1 {
    public static final o b = new o(1, 0);
    public static final o c = new o(1, 1);
    public static final o d = new o(1, 2);
    public static final o e = new o(1, 3);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ o(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return Unit.a;
            case 1:
                ((Number) obj).intValue();
                return null;
            case 2:
                List list = (List) obj;
                return new A(((Number) list.get(0)).intValue(), ((Number) list.get(1)).intValue());
            case 3:
                ((Number) obj).intValue();
                return K.a;
            default:
                ((Number) obj).intValue();
                return null;
        }
    }
}
