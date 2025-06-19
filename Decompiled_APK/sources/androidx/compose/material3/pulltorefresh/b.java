package androidx.compose.material3.pulltorefresh;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class b extends r implements Function2 {
    public final /* synthetic */ c a;
    public final /* synthetic */ q b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ androidx.compose.ui.q d;
    public final /* synthetic */ long e;
    public final /* synthetic */ long f;
    public final /* synthetic */ float g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, q qVar, boolean z, androidx.compose.ui.q qVar2, long j, long j2, float f, int i) {
        super(2);
        this.a = cVar;
        this.b = qVar;
        this.c = z;
        this.d = qVar2;
        this.e = j;
        this.f = j2;
        this.g = f;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(1572865);
        androidx.compose.ui.q qVar = this.d;
        long j = this.e;
        this.a.a(this.b, this.c, qVar, j, this.f, this.g, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
