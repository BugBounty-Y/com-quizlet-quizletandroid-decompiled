package androidx.compose.ui.scrollcapture;

import android.graphics.Point;
import android.view.ScrollCaptureTarget;
import android.view.View;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.a0;
import androidx.compose.ui.semantics.o;
import androidx.compose.ui.semantics.p;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3124d5;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q5;
import java.util.function.Consumer;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.E;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class l {
    public final InterfaceC0773a0 a = C0776c.z(Boolean.FALSE);

    public final void a(@NotNull View view, @NotNull p pVar, @NotNull CoroutineContext coroutineContext, @NotNull Consumer<ScrollCaptureTarget> consumer) {
        androidx.compose.runtime.collection.b bVar = new androidx.compose.runtime.collection.b(new m[16]);
        AbstractC3124d5.d(pVar.a(), 0, new k(1, bVar, androidx.compose.runtime.collection.b.class, "add", "add(Ljava/lang/Object;)Z", 8, 0));
        bVar.s(kotlin.comparisons.a.a(d.c, d.d));
        m mVar = (m) (bVar.l() ? null : bVar.a[bVar.c - 1]);
        if (mVar == null) {
            return;
        }
        kotlinx.coroutines.internal.d dVarC = E.c(coroutineContext);
        o oVar = mVar.a;
        androidx.compose.ui.unit.i iVar = mVar.c;
        f fVar = new f(oVar, iVar, dVarC, this);
        a0 a0Var = mVar.d;
        androidx.compose.ui.geometry.c cVarO = AbstractC0897s.g(a0Var).o(a0Var, true);
        long jB = P5.b(iVar.a, iVar.b);
        ScrollCaptureTarget scrollCaptureTargetI = androidx.camera.camera2.internal.compat.quirk.c.i(view, F.x(Q5.b(cVarO)), new Point((int) (jB >> 32), (int) (jB & 4294967295L)), fVar);
        scrollCaptureTargetI.setScrollBounds(F.x(iVar));
        consumer.accept(scrollCaptureTargetI);
    }
}
