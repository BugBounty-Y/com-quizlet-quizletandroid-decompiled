package androidx.compose.foundation.gestures.snapping;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.G;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class d extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ G b;
    public final /* synthetic */ r c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public d(G g, Function1 function1, int i) {
        super(1);
        this.a = i;
        switch (i) {
            case 1:
                this.b = g;
                this.c = (r) function1;
                super(1);
                break;
            default:
                this.b = g;
                this.c = (r) function1;
                break;
        }
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r0v4, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                float fFloatValue = ((Number) obj).floatValue();
                G g = this.b;
                float f = g.a - fFloatValue;
                g.a = f;
                this.c.invoke(Float.valueOf(f));
                break;
            default:
                float fFloatValue2 = ((Number) obj).floatValue();
                G g2 = this.b;
                float f2 = g2.a - fFloatValue2;
                g2.a = f2;
                this.c.invoke(Float.valueOf(f2));
                break;
        }
        return Unit.a;
    }
}
