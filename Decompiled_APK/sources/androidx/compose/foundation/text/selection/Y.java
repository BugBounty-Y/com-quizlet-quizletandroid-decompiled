package androidx.compose.foundation.text.selection;

import android.os.Build;
import androidx.compose.foundation.G0;
import androidx.compose.foundation.t0;
import androidx.compose.runtime.InterfaceC0773a0;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class Y extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.unit.b b;
    public final /* synthetic */ InterfaceC0773a0 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ Y(androidx.compose.ui.unit.b bVar, InterfaceC0773a0 interfaceC0773a0, int i) {
        super(1);
        this.a = i;
        this.b = bVar;
        this.c = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                long j = ((androidx.compose.ui.unit.g) obj).a;
                float fB = androidx.compose.ui.unit.g.b(j);
                androidx.compose.ui.unit.b bVar = this.b;
                this.c.setValue(new androidx.compose.ui.unit.j(R5.a(bVar.m0(fB), bVar.m0(androidx.compose.ui.unit.g.a(j)))));
                return Unit.a;
            case 1:
                androidx.compose.foundation.gestures.D d = new androidx.compose.foundation.gestures.D(1, (Function0) obj);
                Y y = new Y(this.b, this.c, 0);
                if (t0.a()) {
                    return t0.b(d, y, Build.VERSION.SDK_INT == 28 ? G0.b : G0.c);
                }
                throw new UnsupportedOperationException("Magnifier is only supported on API level 28 and higher.");
            case 2:
                long j2 = ((androidx.compose.ui.unit.g) obj).a;
                float fB2 = androidx.compose.ui.unit.g.b(j2);
                androidx.compose.ui.unit.b bVar2 = this.b;
                this.c.setValue(new androidx.compose.ui.unit.j(R5.a(bVar2.m0(fB2), bVar2.m0(androidx.compose.ui.unit.g.a(j2)))));
                return Unit.a;
            default:
                androidx.compose.foundation.gestures.D d2 = new androidx.compose.foundation.gestures.D(2, (Function0) obj);
                Y y2 = new Y(this.b, this.c, 2);
                if (t0.a()) {
                    return t0.b(d2, y2, Build.VERSION.SDK_INT == 28 ? G0.b : G0.c);
                }
                throw new UnsupportedOperationException("Magnifier is only supported on API level 28 and higher.");
        }
    }
}
