package androidx.compose.material3;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import kotlin.Unit;

/* renamed from: androidx.compose.material3.e0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0608e0 extends kotlin.jvm.internal.r implements kotlin.jvm.functions.c {
    public static final C0608e0 b = new C0608e0(3, 0);
    public static final C0608e0 c = new C0608e0(3, 1);
    public static final C0608e0 d = new C0608e0(3, 2);
    public static final C0608e0 e = new C0608e0(3, 3);
    public static final C0608e0 f = new C0608e0(3, 4);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0608e0(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj2;
                if ((((Number) obj3).intValue() & 17) == 16) {
                    C0814p c0814p = (C0814p) interfaceC0806l;
                    if (c0814p.x()) {
                        c0814p.Q();
                    }
                }
                return Unit.a;
            case 1:
                InterfaceC0806l interfaceC0806l2 = (InterfaceC0806l) obj2;
                if ((((Number) obj3).intValue() & 17) == 16) {
                    C0814p c0814p2 = (C0814p) interfaceC0806l2;
                    if (c0814p2.x()) {
                        c0814p2.Q();
                    }
                }
                return Unit.a;
            case 2:
                InterfaceC0806l interfaceC0806l3 = (InterfaceC0806l) obj2;
                if ((((Number) obj3).intValue() & 17) == 16) {
                    C0814p c0814p3 = (C0814p) interfaceC0806l3;
                    if (c0814p3.x()) {
                        c0814p3.Q();
                    }
                }
                return Unit.a;
            case 3:
                InterfaceC0806l interfaceC0806l4 = (InterfaceC0806l) obj2;
                if ((((Number) obj3).intValue() & 17) == 16) {
                    C0814p c0814p4 = (C0814p) interfaceC0806l4;
                    if (c0814p4.x()) {
                        c0814p4.Q();
                    }
                }
                return Unit.a;
            default:
                androidx.compose.ui.layout.M m = (androidx.compose.ui.layout.M) obj;
                long j = ((androidx.compose.ui.unit.a) obj3).a;
                int iM0 = m.m0(AbstractC0666j3.a);
                int i = iM0 * 2;
                androidx.compose.ui.layout.W wB = ((androidx.compose.ui.layout.J) obj2).B(L5.o(0, i, j));
                return m.n0(wB.a, wB.b - i, kotlin.collections.V.c(), new androidx.compose.foundation.lazy.u(wB, iM0, 2));
        }
    }
}
