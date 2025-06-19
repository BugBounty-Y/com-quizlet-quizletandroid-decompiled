package androidx.compose.ui.window;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class n extends kotlin.jvm.internal.r implements Function2 {
    public static final n b = new n(2, 0);
    public static final n c = new n(2, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ n(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
                if ((((Number) obj2).intValue() & 3) == 2) {
                    C0814p c0814p = (C0814p) interfaceC0806l;
                    if (c0814p.x()) {
                        c0814p.Q();
                    }
                }
                break;
            default:
                InterfaceC0806l interfaceC0806l2 = (InterfaceC0806l) obj;
                if ((((Number) obj2).intValue() & 3) == 2) {
                    C0814p c0814p2 = (C0814p) interfaceC0806l2;
                    if (c0814p2.x()) {
                        c0814p2.Q();
                    }
                }
                break;
        }
        return Unit.a;
    }
}
