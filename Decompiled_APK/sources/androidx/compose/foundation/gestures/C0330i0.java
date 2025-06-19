package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.gestures.i0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0330i0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlin.jvm.internal.G b;
    public final /* synthetic */ InterfaceC0334k0 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0330i0(kotlin.jvm.internal.G g, InterfaceC0334k0 interfaceC0334k0, int i) {
        super(2);
        this.a = i;
        this.b = g;
        this.c = interfaceC0334k0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                float fFloatValue = ((Number) obj).floatValue();
                ((Number) obj2).floatValue();
                kotlin.jvm.internal.G g = this.b;
                float f = g.a;
                g.a = this.c.a(fFloatValue - f) + f;
                break;
            default:
                float fFloatValue2 = ((Number) obj).floatValue();
                ((Number) obj2).floatValue();
                kotlin.jvm.internal.G g2 = this.b;
                g2.a += this.c.a(fFloatValue2 - g2.a);
                break;
        }
        return Unit.a;
    }
}
