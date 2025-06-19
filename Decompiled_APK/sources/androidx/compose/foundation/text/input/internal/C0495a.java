package androidx.compose.foundation.text.input.internal;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.text.input.internal.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0495a extends kotlin.jvm.internal.r implements Function1 {
    public static final C0495a b = new C0495a(1, 0);
    public static final C0495a c = new C0495a(1, 1);
    public static final C0495a d = new C0495a(1, 2);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0495a(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final /* synthetic */ Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                ((Number) obj).longValue();
                break;
            case 1:
                break;
            default:
                int i = ((androidx.compose.ui.text.input.l) obj).a;
                break;
        }
        return Unit.a;
    }
}
