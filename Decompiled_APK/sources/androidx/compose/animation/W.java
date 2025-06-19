package androidx.compose.animation;

import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class W extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ long c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ W(Object obj, long j, long j2, Object obj2, int i) {
        super(1);
        this.a = i;
        this.d = obj;
        this.b = j;
        this.c = j2;
        this.e = obj2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
                long j = this.b;
                long j2 = this.c;
                androidx.activity.compose.g gVar = (androidx.activity.compose.g) this.e;
                androidx.compose.ui.layout.W w = (androidx.compose.ui.layout.W) this.d;
                v.getClass();
                long jB = P5.b(((int) (j >> 32)) + ((int) (j2 >> 32)), ((int) (j & 4294967295L)) + ((int) (j2 & 4294967295L)));
                androidx.compose.ui.layout.V.a(v, w);
                w.s0(androidx.compose.ui.unit.h.d(jB, w.e), DefinitionKt.NO_Float_VALUE, gVar);
                break;
            default:
                androidx.compose.ui.node.G g = (androidx.compose.ui.node.G) obj;
                g.b();
                androidx.compose.ui.graphics.drawscope.d.J(g, (androidx.compose.ui.graphics.X) this.d, this.b, this.c, DefinitionKt.NO_Float_VALUE, (androidx.compose.ui.graphics.drawscope.e) this.e, 104);
                break;
        }
        return Unit.a;
    }
}
