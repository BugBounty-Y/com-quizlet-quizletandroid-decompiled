package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.z7;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class J1 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Function2 c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ J1(long j, Object obj, Function2 function2, int i, int i2) {
        super(2);
        this.a = i2;
        this.b = j;
        this.e = obj;
        this.c = function2;
        this.d = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.d | 1);
                androidx.compose.material3.tokens.G g = (androidx.compose.material3.tokens.G) this.e;
                Function2 function2 = this.c;
                L1.c(this.b, g, function2, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Number) obj2).intValue();
                int i = this.d | 1;
                io.reactivex.rxjava3.exceptions.a.b(i, this.b, (InterfaceC0806l) obj, (androidx.glance.appwidget.J0) this.e, this.c);
                break;
            default:
                ((Number) obj2).intValue();
                int i2 = this.d | 1;
                androidx.glance.layout.c cVar = (androidx.glance.layout.c) this.e;
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.c;
                z7.e(this.b, cVar, dVar, (InterfaceC0806l) obj, i2);
                break;
        }
        return Unit.a;
    }
}
