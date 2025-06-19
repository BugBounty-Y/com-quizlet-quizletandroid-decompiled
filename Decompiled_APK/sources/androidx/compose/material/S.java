package androidx.compose.material;

import androidx.compose.animation.core.C0238e;
import androidx.compose.runtime.W0;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class S extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ S(long j, W0 w0, int i) {
        super(1);
        this.a = i;
        this.b = j;
        this.c = w0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) throws Throwable {
        Object obj2 = this.c;
        switch (this.a) {
            case 0:
                androidx.compose.ui.graphics.drawscope.d.I((androidx.compose.ui.graphics.drawscope.d) obj, this.b, 0L, 0L, kotlin.ranges.l.b(((Number) ((W0) obj2).getValue()).floatValue(), DefinitionKt.NO_Float_VALUE, 1.0f), 118);
                break;
            case 1:
                androidx.compose.ui.graphics.drawscope.d.I((androidx.compose.ui.graphics.drawscope.d) obj, this.b, 0L, 0L, kotlin.ranges.l.b(((Number) ((W0) obj2).getValue()).floatValue(), DefinitionKt.NO_Float_VALUE, 1.0f), 118);
                break;
            default:
                long jC = androidx.compose.ui.unit.h.c(((androidx.compose.ui.unit.h) ((C0238e) obj).d()).a, this.b);
                int i = androidx.compose.foundation.lazy.layout.E.t;
                androidx.compose.foundation.lazy.layout.E e = (androidx.compose.foundation.lazy.layout.E) obj2;
                e.g(jC);
                e.c.invoke();
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S(androidx.compose.foundation.lazy.layout.E e, long j) {
        super(1);
        this.a = 2;
        this.c = e;
        this.b = j;
    }
}
