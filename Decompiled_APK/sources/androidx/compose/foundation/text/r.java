package androidx.compose.foundation.text;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0995g;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class r extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ C0995g a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ androidx.compose.ui.text.L c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;
    public final /* synthetic */ C0491h g;
    public final /* synthetic */ Function1 h;
    public final /* synthetic */ int i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(C0995g c0995g, androidx.compose.ui.q qVar, androidx.compose.ui.text.L l, boolean z, int i, int i2, C0491h c0491h, Function1 function1, int i3) {
        super(2);
        this.a = c0995g;
        this.b = qVar;
        this.c = l;
        this.d = z;
        this.e = i;
        this.f = i2;
        this.g = c0491h;
        this.h = function1;
        this.i = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.i | 1);
        C0995g c0995g = this.a;
        int i = this.e;
        int i2 = this.f;
        AbstractC0484d0.c(c0995g, this.b, this.c, this.d, i, i2, this.g, this.h, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
