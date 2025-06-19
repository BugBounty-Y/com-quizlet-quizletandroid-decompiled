package androidx.compose.foundation.text.input.internal;

import android.os.CancellationSignal;
import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.selection.i0;
import androidx.compose.ui.text.K;
import kotlinx.coroutines.y0;

/* loaded from: classes.dex */
public final /* synthetic */ class q implements CancellationSignal.OnCancelListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ q(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.os.CancellationSignal.OnCancelListener
    public final void onCancel() {
        switch (this.a) {
            case 0:
                i0 i0Var = (i0) this.b;
                if (i0Var != null) {
                    C0492h0 c0492h0 = i0Var.d;
                    if (c0492h0 != null) {
                        c0492h0.e(K.b);
                    }
                    C0492h0 c0492h02 = i0Var.d;
                    if (c0492h02 != null) {
                        c0492h02.f(K.b);
                        break;
                    }
                }
                break;
            default:
                ((y0) this.b).j(null);
                break;
        }
    }
}
