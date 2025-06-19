package androidx.compose.foundation;

import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0553v extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ androidx.compose.ui.graphics.X b;
    public final /* synthetic */ long c;
    public final /* synthetic */ float d;
    public final /* synthetic */ float e;
    public final /* synthetic */ long f;
    public final /* synthetic */ long g;
    public final /* synthetic */ androidx.compose.ui.graphics.drawscope.h h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0553v(boolean z, androidx.compose.ui.graphics.X x, long j, float f, float f2, long j2, long j3, androidx.compose.ui.graphics.drawscope.h hVar) {
        super(1);
        this.a = z;
        this.b = x;
        this.c = j;
        this.d = f;
        this.e = f2;
        this.f = j2;
        this.g = j3;
        this.h = hVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.node.G g = (androidx.compose.ui.node.G) obj;
        g.b();
        if (this.a) {
            androidx.compose.ui.graphics.drawscope.d.q(g, this.b, 0L, 0L, this.c, null, 246);
        } else {
            long j = this.c;
            float fB = androidx.compose.ui.geometry.a.b(j);
            float f = this.d;
            if (fB < f) {
                float f2 = this.e;
                androidx.compose.ui.graphics.drawscope.b bVar = g.a;
                float fD = androidx.compose.ui.geometry.e.d(bVar.g());
                float f3 = this.e;
                float f4 = fD - f3;
                float fB2 = androidx.compose.ui.geometry.e.b(bVar.g()) - f3;
                androidx.compose.ui.graphics.X x = this.b;
                long j2 = this.c;
                com.quizlet.data.repository.folderset.c cVar = bVar.b;
                long jR = cVar.r();
                cVar.o().e();
                try {
                    ((androidx.appcompat.app.L) cVar.b).H(f2, f2, f4, fB2, 0);
                    androidx.compose.ui.graphics.drawscope.d.q(g, x, 0L, 0L, j2, null, 246);
                } finally {
                    androidx.compose.animation.d0.y(cVar, jR);
                }
            } else {
                androidx.compose.ui.graphics.drawscope.d.q(g, this.b, this.f, this.g, AbstractC0460p.t(j, f), this.h, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_BACKWARD_COMPATIBILITY);
            }
        }
        return Unit.a;
    }
}
