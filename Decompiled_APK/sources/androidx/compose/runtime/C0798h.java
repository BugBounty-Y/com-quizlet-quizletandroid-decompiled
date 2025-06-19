package androidx.compose.runtime;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.runtime.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0798h extends kotlin.jvm.internal.r implements Function2 {
    public static final C0798h b = new C0798h(2, 0);
    public static final C0798h c = new C0798h(2, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0798h(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
                int iIntValue = ((Number) obj2).intValue();
                C0814p c0814p = (C0814p) interfaceC0806l;
                if (!c0814p.N(iIntValue & 1, (iIntValue & 3) != 2)) {
                    c0814p.Q();
                }
                break;
            case 1:
                InterfaceC0806l interfaceC0806l2 = (InterfaceC0806l) obj;
                int iIntValue2 = ((Number) obj2).intValue();
                C0814p c0814p2 = (C0814p) interfaceC0806l2;
                if (!c0814p2.N(iIntValue2 & 1, (iIntValue2 & 3) != 2)) {
                    c0814p2.Q();
                }
                break;
            default:
                ((androidx.compose.ui.node.E) obj).v = true;
                Unit unit = Unit.a;
                break;
        }
        return Unit.a;
    }
}
