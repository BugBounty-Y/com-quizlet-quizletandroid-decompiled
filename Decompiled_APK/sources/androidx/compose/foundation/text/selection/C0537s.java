package androidx.compose.foundation.text.selection;

import androidx.compose.foundation.text.AbstractC0484d0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;

/* renamed from: androidx.compose.foundation.text.selection.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0537s implements InterfaceC0528i {
    public static final C0537s b = new C0537s(0);
    public static final C0537s c = new C0537s(1);
    public static final r d = new r(0);
    public static final r e = new r(1);
    public static final r f = new r(2);
    public static final r g = new r(3);
    public final /* synthetic */ int a;

    public /* synthetic */ C0537s(int i) {
        this.a = i;
    }

    @Override // androidx.compose.foundation.text.selection.InterfaceC0528i
    public long a(C0534o c0534o, int i) {
        switch (this.a) {
            case 0:
                String str = c0534o.f.a.a.a;
                return AbstractC3205m5.c(AbstractC0484d0.u(i, str), AbstractC0484d0.t(i, str));
            default:
                return c0534o.f.l(i);
        }
    }
}
