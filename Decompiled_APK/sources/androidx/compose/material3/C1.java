package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class C1 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.graphics.painter.b a;
    public final /* synthetic */ String b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ long d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1(androidx.compose.ui.graphics.painter.b bVar, String str, androidx.compose.ui.q qVar, long j, int i, int i2) {
        super(2);
        this.a = bVar;
        this.b = str;
        this.c = qVar;
        this.d = j;
        this.e = i;
        this.f = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.e | 1);
        String str = this.b;
        D1.a(this.a, str, this.c, this.d, (InterfaceC0806l) obj, iH, this.f);
        return Unit.a;
    }
}
