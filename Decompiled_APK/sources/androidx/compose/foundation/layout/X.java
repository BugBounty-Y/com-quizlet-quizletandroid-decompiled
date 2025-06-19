package androidx.compose.foundation.layout;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class X extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ InterfaceC0388h b;
    public final /* synthetic */ InterfaceC0394k c;
    public final /* synthetic */ int d;
    public final /* synthetic */ int e;
    public final /* synthetic */ I f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ int h;
    public final /* synthetic */ int i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public X(androidx.compose.ui.q qVar, InterfaceC0388h interfaceC0388h, InterfaceC0394k interfaceC0394k, int i, int i2, I i3, androidx.compose.runtime.internal.d dVar, int i4, int i5) {
        super(2);
        this.a = qVar;
        this.b = interfaceC0388h;
        this.c = interfaceC0394k;
        this.d = i;
        this.e = i2;
        this.f = i3;
        this.g = dVar;
        this.h = i4;
        this.i = i5;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.h | 1);
        androidx.compose.runtime.internal.d dVar = this.g;
        InterfaceC0394k interfaceC0394k = this.c;
        int i = this.e;
        AbstractC0377b0.b(this.a, this.b, interfaceC0394k, this.d, i, this.f, dVar, (InterfaceC0806l) obj, iH, this.i);
        return Unit.a;
    }
}
