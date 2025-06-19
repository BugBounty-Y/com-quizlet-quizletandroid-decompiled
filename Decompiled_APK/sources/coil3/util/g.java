package coil3.util;

import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import kotlin.Unit;
import kotlin.p;
import kotlin.r;
import kotlinx.coroutines.C5028l;

/* loaded from: classes.dex */
public final class g implements InterfaceC1250k {
    public final /* synthetic */ C5028l a;

    public g(C5028l c5028l) {
        this.a = c5028l;
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onStart(J j) {
        p pVar = r.b;
        this.a.resumeWith(Unit.a);
    }
}
