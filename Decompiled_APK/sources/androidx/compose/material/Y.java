package androidx.compose.material;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class Y extends kotlin.jvm.internal.r implements Function1 {
    public static final Y b = new Y(1, 0);
    public static final Y c = new Y(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ Y(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return Boolean.TRUE;
            default:
                androidx.compose.ui.semantics.t.d((androidx.compose.ui.semantics.v) obj);
                return Unit.a;
        }
    }
}
