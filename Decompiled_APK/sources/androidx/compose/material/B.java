package androidx.compose.material;

import androidx.compose.material3.D1;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.vector.C0867f;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class B extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ String b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ long d;
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(androidx.compose.ui.graphics.painter.b bVar, String str, androidx.compose.ui.q qVar, long j, int i) {
        super(2);
        this.f = bVar;
        this.b = str;
        this.c = qVar;
        this.d = j;
        this.e = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                C.a((androidx.compose.ui.graphics.painter.b) this.f, this.b, this.c, this.d, (InterfaceC0806l) obj, C0776c.H(this.e | 1));
                break;
            default:
                ((Number) obj2).intValue();
                int iH = C0776c.H(1);
                C0867f c0867f = (C0867f) this.f;
                String str = this.b;
                D1.b(c0867f, str, this.c, this.d, (InterfaceC0806l) obj, iH, this.e);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(C0867f c0867f, String str, androidx.compose.ui.q qVar, long j, int i, int i2) {
        super(2);
        this.f = c0867f;
        this.b = str;
        this.c = qVar;
        this.d = j;
        this.e = i2;
    }
}
