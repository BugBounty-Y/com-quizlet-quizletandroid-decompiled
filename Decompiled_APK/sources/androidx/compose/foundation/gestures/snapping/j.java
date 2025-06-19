package androidx.compose.foundation.gestures.snapping;

import androidx.compose.animation.core.C0254m;
import androidx.compose.foundation.gestures.G0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.G;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class j extends r implements Function1 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ float b;
    public final /* synthetic */ G c;
    public final /* synthetic */ G0 d;
    public final /* synthetic */ r e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(float f, G g, G0 g0, d dVar) {
        super(1);
        this.b = f;
        this.c = g;
        this.d = g0;
        this.e = dVar;
    }

    /* JADX WARN: Type inference failed for: r5v2, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                C0254m c0254m = (C0254m) obj;
                float fAbs = Math.abs(((Number) ((L0) c0254m.e).getValue()).floatValue());
                float f = this.b;
                float fAbs2 = Math.abs(f);
                InterfaceC0773a0 interfaceC0773a0 = c0254m.e;
                G g = this.c;
                d dVar = (d) this.e;
                G0 g0 = this.d;
                if (fAbs >= fAbs2) {
                    float fC = l.c(((Number) ((L0) interfaceC0773a0).getValue()).floatValue(), f);
                    float f2 = fC - g.a;
                    float fA = g0.a(f2);
                    dVar.invoke(Float.valueOf(fA));
                    if (Math.abs(f2 - fA) > 0.5f) {
                        c0254m.a();
                    }
                    c0254m.a();
                    g.a = fC;
                } else {
                    L0 l0 = (L0) interfaceC0773a0;
                    float fFloatValue = ((Number) l0.getValue()).floatValue() - g.a;
                    float fA2 = g0.a(fFloatValue);
                    dVar.invoke(Float.valueOf(fA2));
                    if (Math.abs(fFloatValue - fA2) > 0.5f) {
                        c0254m.a();
                    }
                    g.a = ((Number) l0.getValue()).floatValue();
                }
                break;
            default:
                C0254m c0254m2 = (C0254m) obj;
                float fC2 = l.c(((Number) ((L0) c0254m2.e).getValue()).floatValue(), this.b);
                G g2 = this.c;
                float f3 = fC2 - g2.a;
                float fA3 = this.d.a(f3);
                this.e.invoke(Float.valueOf(fA3));
                if (Math.abs(f3 - fA3) > 0.5f || fC2 != ((Number) ((L0) c0254m2.e).getValue()).floatValue()) {
                    c0254m2.a();
                }
                g2.a += fA3;
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public j(float f, G g, G0 g0, Function1 function1) {
        super(1);
        this.b = f;
        this.c = g;
        this.d = g0;
        this.e = (r) function1;
    }
}
