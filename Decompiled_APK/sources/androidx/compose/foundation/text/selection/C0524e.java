package androidx.compose.foundation.text.selection;

import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.text.selection.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0524e extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ InterfaceC0533n a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0524e(InterfaceC0533n interfaceC0533n, boolean z, boolean z2) {
        super(1);
        this.a = interfaceC0533n;
        this.b = z;
        this.c = z2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.semantics.v vVar = (androidx.compose.ui.semantics.v) obj;
        long jA = this.a.a();
        ((androidx.compose.ui.semantics.k) vVar).b(H.c, new G(this.b ? androidx.compose.foundation.text.U.b : androidx.compose.foundation.text.U.c, jA, this.c ? 1 : 3, Q4.h(jA)));
        return Unit.a;
    }
}
