package androidx.compose.material;

import androidx.compose.material3.A2;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class T extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ int e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ T(long j, Function0 function0, boolean z, int i, int i2) {
        super(2);
        this.a = i2;
        this.b = j;
        this.c = function0;
        this.d = z;
        this.e = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.e | 1);
                Function0 function0 = this.c;
                boolean z = this.d;
                Z.b(this.b, function0, z, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.e | 1);
                Function0 function02 = this.c;
                boolean z2 = this.d;
                A2.c(this.b, function02, z2, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}
