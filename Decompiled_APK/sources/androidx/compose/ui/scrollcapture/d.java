package androidx.compose.ui.scrollcapture;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class d extends r implements Function1 {
    public static final d b = new d(1, 0);
    public static final d c = new d(1, 1);
    public static final d d = new d(1, 2);
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
                ((Number) obj).longValue();
                return Unit.a;
            case 1:
                return Integer.valueOf(((m) obj).b);
            default:
                return Integer.valueOf(((m) obj).c.a());
        }
    }
}
