package androidx.compose.material3.pulltorefresh;

import androidx.appcompat.app.L;
import androidx.compose.animation.core.C0238e;
import androidx.compose.animation.core.M0;
import androidx.compose.animation.d0;
import androidx.compose.ui.node.G;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class d extends r implements Function1 {
    public static final d b = new d(1, 0);
    public static final d c = new d(1, 1);
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
                G g = (G) obj;
                com.quizlet.data.repository.folderset.c cVarE0 = g.e0();
                long jR = cVarE0.r();
                cVarE0.o().e();
                try {
                    ((L) cVarE0.b).H(-3.4028235E38f, DefinitionKt.NO_Float_VALUE, Float.MAX_VALUE, Float.MAX_VALUE, 1);
                    g.b();
                    d0.y(cVarE0, jR);
                    return Unit.a;
                } catch (Throwable th) {
                    d0.y(cVarE0, jR);
                    throw th;
                }
            default:
                return new q(new C0238e(Float.valueOf(((Number) obj).floatValue()), M0.a, null, 12));
        }
    }
}
