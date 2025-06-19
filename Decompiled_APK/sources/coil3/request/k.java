package coil3.request;

import androidx.lifecycle.C;
import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import coil3.s;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3491m;
import kotlin.Unit;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class k implements n, InterfaceC1250k {
    public final C a;
    public final InterfaceC5025j0 b;

    public k(C c, InterfaceC5025j0 interfaceC5025j0) {
        this.a = c;
        this.b = interfaceC5025j0;
    }

    @Override // coil3.request.n
    public final Object a(s sVar) throws Throwable {
        Object objB = AbstractC3491m.b(this.a, sVar);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
    }

    @Override // coil3.request.n
    public final void b() {
        this.a.b(this);
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onDestroy(J j) {
        this.b.j(null);
    }

    @Override // coil3.request.n
    public final void start() {
        this.a.a(this);
    }
}
