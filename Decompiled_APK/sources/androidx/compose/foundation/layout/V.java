package androidx.compose.foundation.layout;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class V extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ int c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ InterfaceC4938g h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public V(androidx.compose.ui.q qVar, C0384f c0384f, C0380d c0380d, int i, int i2, I i3, androidx.compose.runtime.internal.d dVar, int i4) {
        super(2);
        this.b = qVar;
        this.e = c0384f;
        this.f = c0380d;
        this.c = i;
        this.d = i2;
        this.g = i3;
        this.h = dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(1575937);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.h;
                int i = this.c;
                int i2 = this.d;
                AbstractC0377b0.a(this.b, (C0384f) this.e, (C0380d) this.f, i, i2, (I) this.g, dVar, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.c | 1);
                Function1 function1 = (Function1) this.f;
                androidx.compose.ui.viewinterop.k.b((Function1) this.e, this.b, function1, (Function1) this.g, (Function1) this.h, (InterfaceC0806l) obj, iH2, this.d);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public V(Function1 function1, androidx.compose.ui.q qVar, Function1 function12, Function1 function13, Function1 function14, int i, int i2) {
        super(2);
        this.e = function1;
        this.b = qVar;
        this.f = function12;
        this.g = function13;
        this.h = function14;
        this.c = i;
        this.d = i2;
    }
}
