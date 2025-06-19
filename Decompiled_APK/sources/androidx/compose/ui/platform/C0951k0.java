package androidx.compose.ui.platform;

import android.graphics.Matrix;
import android.view.View;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.ui.platform.k0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0951k0 extends kotlin.jvm.internal.r implements Function2 {
    public static final C0951k0 b = new C0951k0(2, 0);
    public static final C0951k0 c = new C0951k0(2, 1);
    public static final C0951k0 d = new C0951k0(2, 2);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0951k0(int i, int i2) {
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
            case 1:
                ((InterfaceC0959o0) obj).J((Matrix) obj2);
                break;
            default:
                ((Matrix) obj2).set(((View) obj).getMatrix());
                break;
        }
        return Unit.a;
    }
}
