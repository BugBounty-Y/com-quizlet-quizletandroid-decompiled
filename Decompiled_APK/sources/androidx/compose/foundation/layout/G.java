package androidx.compose.foundation.layout;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class G extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ InterfaceC0388h c;
    public final /* synthetic */ InterfaceC0394k d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;
    public final /* synthetic */ I g;
    public final /* synthetic */ androidx.compose.runtime.internal.d h;
    public final /* synthetic */ int i;
    public final /* synthetic */ int j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(int i, androidx.compose.ui.q qVar, InterfaceC0388h interfaceC0388h, InterfaceC0394k interfaceC0394k, int i2, int i3, I i4, androidx.compose.runtime.internal.d dVar, int i5, int i6) {
        super(2);
        this.a = i;
        this.b = qVar;
        this.c = interfaceC0388h;
        this.d = interfaceC0394k;
        this.e = i2;
        this.f = i3;
        this.g = i4;
        this.h = dVar;
        this.i = i5;
        this.j = i6;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.i | 1);
        androidx.compose.runtime.internal.d dVar = this.h;
        InterfaceC0388h interfaceC0388h = this.c;
        InterfaceC0394k interfaceC0394k = this.d;
        int i = this.f;
        AbstractC0382e.b(this.a, this.b, interfaceC0388h, interfaceC0394k, this.e, i, this.g, dVar, (InterfaceC0806l) obj, iH, this.j);
        return Unit.a;
    }
}
