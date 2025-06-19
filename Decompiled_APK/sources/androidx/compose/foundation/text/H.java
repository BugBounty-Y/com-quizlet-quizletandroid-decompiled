package androidx.compose.foundation.text;

import androidx.compose.ui.platform.C0957n0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class H extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ C0492h0 a;
    public final /* synthetic */ androidx.compose.ui.focus.p b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ androidx.compose.foundation.text.selection.i0 e;
    public final /* synthetic */ androidx.compose.ui.text.input.s f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public H(C0492h0 c0492h0, androidx.compose.ui.focus.p pVar, boolean z, boolean z2, androidx.compose.foundation.text.selection.i0 i0Var, androidx.compose.ui.text.input.s sVar) {
        super(1);
        this.a = c0492h0;
        this.b = pVar;
        this.c = z;
        this.d = z2;
        this.e = i0Var;
        this.f = sVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.platform.Q0 q0;
        long j = ((androidx.compose.ui.geometry.b) obj).a;
        C0492h0 c0492h0 = this.a;
        if (!c0492h0.b()) {
            this.b.b();
        } else if (!this.c && (q0 = c0492h0.c) != null) {
            ((C0957n0) q0).b();
        }
        if (c0492h0.b() && this.d) {
            if (c0492h0.a() != V.b) {
                K0 k0D = c0492h0.d();
                if (k0D != null) {
                    int iG = this.f.g(k0D.b(j, true));
                    c0492h0.t.invoke(androidx.compose.ui.text.input.A.a((androidx.compose.ui.text.input.A) c0492h0.d.b, null, AbstractC3205m5.c(iG, iG), 5));
                    if (c0492h0.a.a.a.length() > 0) {
                        ((androidx.compose.runtime.L0) c0492h0.k).setValue(V.c);
                    }
                }
            } else {
                this.e.g(new androidx.compose.ui.geometry.b(j));
            }
        }
        return Unit.a;
    }
}
