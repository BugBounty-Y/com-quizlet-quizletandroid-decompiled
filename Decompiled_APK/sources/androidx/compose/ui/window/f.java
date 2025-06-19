package androidx.compose.ui.window;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class f extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.i a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ y d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(androidx.compose.ui.i iVar, long j, Function0 function0, y yVar, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        super(2);
        this.a = iVar;
        this.b = j;
        this.c = function0;
        this.d = yVar;
        this.e = dVar;
        this.f = i;
        this.g = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.f | 1);
        y yVar = this.d;
        androidx.compose.runtime.internal.d dVar = this.e;
        Function0 function0 = this.c;
        l.b(this.a, this.b, function0, yVar, dVar, (InterfaceC0806l) obj, iH, this.g);
        return Unit.a;
    }
}
