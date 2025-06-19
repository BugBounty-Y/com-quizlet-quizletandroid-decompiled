package androidx.compose.ui.layout;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3320b;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class b0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Function2 e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b0(androidx.compose.ui.q qVar, Function2 function2, int i, int i2) {
        super(2);
        this.d = qVar;
        this.e = function2;
        this.b = i;
        this.c = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.b | 1);
                Function2 function2 = this.e;
                int i = this.c;
                AbstractC0897s.c((androidx.compose.ui.q) this.d, function2, (InterfaceC0806l) obj, iH, i);
                break;
            default:
                ((Number) obj2).intValue();
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.e;
                int i2 = this.b;
                AbstractC3320b.a((androidx.glance.p) this.d, i2, dVar, (InterfaceC0806l) obj, 3073, this.c);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b0(androidx.glance.p pVar, int i, androidx.compose.runtime.internal.d dVar, int i2, int i3) {
        super(2);
        this.d = pVar;
        this.b = i;
        this.e = dVar;
        this.c = i3;
    }
}
