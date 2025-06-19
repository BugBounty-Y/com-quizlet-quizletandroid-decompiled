package androidx.compose.foundation;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0476t extends kotlin.jvm.internal.r implements Function1 {
    public static final C0476t b = new C0476t(1, 0);
    public static final C0476t c = new C0476t(1, 1);
    public static final C0476t d = new C0476t(1, 2);
    public static final C0476t e = new C0476t(1, 3);
    public static final C0476t f = new C0476t(1, 4);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0476t(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                ((androidx.compose.ui.node.G) obj).b();
                return Unit.a;
            case 1:
                return Unit.a;
            case 2:
                ((Number) obj).longValue();
                return Unit.a;
            case 3:
                androidx.compose.ui.semantics.t.g((androidx.compose.ui.semantics.v) obj, androidx.compose.ui.semantics.g.c);
                return Unit.a;
            default:
                return new N0(((Number) obj).intValue());
        }
    }
}
