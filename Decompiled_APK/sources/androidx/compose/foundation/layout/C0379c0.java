package androidx.compose.foundation.layout;

import androidx.collection.C0212j;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.layout.c0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0379c0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0381d0 b;
    public final /* synthetic */ InterfaceC0387g0 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0379c0(C0381d0 c0381d0, InterfaceC0387g0 interfaceC0387g0, int i) {
        super(1);
        this.a = i;
        this.b = c0381d0;
        this.c = interfaceC0387g0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int iC;
        int iE;
        int iC2;
        int iE2;
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.W w = (androidx.compose.ui.layout.W) obj;
                if (w != null) {
                    InterfaceC0387g0 interfaceC0387g0 = this.c;
                    iC = interfaceC0387g0.c(w);
                    iE = interfaceC0387g0.e(w);
                } else {
                    iC = 0;
                    iE = 0;
                }
                C0212j c0212j = new C0212j(C0212j.a(iC, iE));
                C0381d0 c0381d0 = this.b;
                c0381d0.f = c0212j;
                c0381d0.c = w;
                break;
            default:
                androidx.compose.ui.layout.W w2 = (androidx.compose.ui.layout.W) obj;
                if (w2 != null) {
                    InterfaceC0387g0 interfaceC0387g02 = this.c;
                    iC2 = interfaceC0387g02.c(w2);
                    iE2 = interfaceC0387g02.e(w2);
                } else {
                    iC2 = 0;
                    iE2 = 0;
                }
                C0212j c0212j2 = new C0212j(C0212j.a(iC2, iE2));
                C0381d0 c0381d02 = this.b;
                c0381d02.g = c0212j2;
                c0381d02.e = w2;
                break;
        }
        return Unit.a;
    }
}
