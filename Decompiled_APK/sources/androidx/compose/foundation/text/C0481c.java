package androidx.compose.foundation.text;

import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.foundation.gestures.n1;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.text.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0481c extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0481c(int i, long j) {
        super(1);
        this.a = i;
        this.b = j;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        long j = this.b;
        switch (this.a) {
            case 0:
                androidx.compose.ui.draw.d dVar = (androidx.compose.ui.draw.d) obj;
                float fD = androidx.compose.ui.geometry.e.d(dVar.a.g()) / 2.0f;
                return dVar.b(new n1(fD, androidx.compose.foundation.text.selection.W.q(dVar, fD), new C0853m(j, 5, Build.VERSION.SDK_INT >= 29 ? C0854n.a.a(j, 5) : new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(j), androidx.compose.ui.graphics.F.E(5))), 2));
            case 1:
                ((androidx.compose.ui.semantics.k) ((androidx.compose.ui.semantics.v) obj)).b(androidx.compose.foundation.text.selection.H.c, new androidx.compose.foundation.text.selection.G(U.a, this.b, 2, true));
                return Unit.a;
            default:
                Long l = (Long) obj;
                if (l == null) {
                    throw new IllegalStateException("Start the timer with startTimer before calling addTime");
                }
                kotlin.time.a aVar = kotlin.time.b.b;
                if (j > 0) {
                    return Long.valueOf(kotlin.time.b.e(j) + l.longValue());
                }
                throw new IllegalArgumentException("Cannot call addTime with a negative duration");
        }
    }
}
