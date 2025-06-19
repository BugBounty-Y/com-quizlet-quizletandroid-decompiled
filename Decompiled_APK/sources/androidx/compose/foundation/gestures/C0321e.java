package androidx.compose.foundation.gestures;

import android.content.Context;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.gestures.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0321e extends kotlin.jvm.internal.r implements Function1 {
    public static final C0321e b = new C0321e(1, 0);
    public static final C0321e c = new C0321e(1, 1);
    public static final C0321e d = new C0321e(1, 2);
    public static final C0321e e = new C0321e(1, 3);
    public static final C0321e f = new C0321e(1, 4);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0321e(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                InterfaceC0803j0 interfaceC0803j0 = (InterfaceC0803j0) obj;
                androidx.compose.runtime.X0 x0 = AndroidCompositionLocals_androidKt.b;
                interfaceC0803j0.getClass();
                if (((Context) C0776c.B(interfaceC0803j0, x0)).getPackageManager().hasSystemFeature("android.software.leanback")) {
                    return AbstractC0325g.b;
                }
                InterfaceC0319d.a.getClass();
                return C0317c.c;
            case 1:
                long j = ((androidx.compose.ui.geometry.b) obj).a;
                return Unit.a;
            case 2:
                return Boolean.TRUE;
            case 3:
                return Boolean.valueOf(!(((androidx.compose.ui.input.pointer.n) obj).i == 2));
            default:
                ((Number) obj).floatValue();
                return Unit.a;
        }
    }
}
