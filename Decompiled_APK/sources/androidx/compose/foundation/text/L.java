package androidx.compose.foundation.text;

import androidx.compose.ui.platform.C0957n0;
import androidx.compose.ui.platform.C0978y0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class L extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(C0492h0 c0492h0, androidx.compose.ui.focus.p pVar, boolean z) {
        super(0);
        this.c = c0492h0;
        this.d = pVar;
        this.b = z;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        androidx.compose.ui.platform.Q0 q0;
        switch (this.a) {
            case 0:
                C0492h0 c0492h0 = (C0492h0) this.c;
                if (!c0492h0.b()) {
                    ((androidx.compose.ui.focus.p) this.d).b();
                } else if (!this.b && (q0 = c0492h0.c) != null) {
                    ((C0957n0) q0).b();
                }
                return Boolean.TRUE;
            default:
                if (this.b) {
                    androidx.savedstate.d dVar = (androidx.savedstate.d) this.c;
                    String key = (String) this.d;
                    Intrinsics.checkNotNullParameter(key, "key");
                    C0978y0 c0978y0 = dVar.a;
                    Intrinsics.checkNotNullParameter(key, "key");
                    synchronized (((com.google.android.gms.internal.mlkit_common.u) c0978y0.f)) {
                    }
                }
                return Unit.a;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(boolean z, androidx.savedstate.d dVar, String str) {
        super(0);
        this.b = z;
        this.c = dVar;
        this.d = str;
    }
}
