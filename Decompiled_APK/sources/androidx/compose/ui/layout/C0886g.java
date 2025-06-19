package androidx.compose.ui.layout;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.ui.layout.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0886g extends kotlin.jvm.internal.r implements Function2 {
    public static final C0886g a = new C0886g(2);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        if ((((Number) obj2).intValue() & 3) == 2) {
            C0814p c0814p = (C0814p) interfaceC0806l;
            if (c0814p.x()) {
                c0814p.Q();
            }
        }
        return Unit.a;
    }
}
