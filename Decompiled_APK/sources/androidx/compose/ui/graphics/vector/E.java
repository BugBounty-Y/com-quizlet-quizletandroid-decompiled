package androidx.compose.ui.graphics.vector;

import androidx.compose.animation.d0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class E extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ F b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ E(F f, int i) {
        super(1);
        this.a = i;
        this.b = f;
    }

    /* JADX WARN: Type inference failed for: r10v3, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                F f = this.b;
                f.d = true;
                f.f.invoke();
                return Unit.a;
            default:
                androidx.compose.ui.graphics.drawscope.d dVar = (androidx.compose.ui.graphics.drawscope.d) obj;
                F f2 = this.b;
                C0864c c0864c = f2.b;
                float f3 = f2.k;
                float f4 = f2.l;
                com.quizlet.data.repository.folderset.c cVarE0 = dVar.e0();
                long jR = cVarE0.r();
                cVarE0.o().e();
                try {
                    ((androidx.appcompat.app.L) cVarE0.b).Q(f3, f4, 0L);
                    c0864c.a(dVar);
                    d0.y(cVarE0, jR);
                    return Unit.a;
                } catch (Throwable th) {
                    d0.y(cVarE0, jR);
                    throw th;
                }
        }
    }
}
