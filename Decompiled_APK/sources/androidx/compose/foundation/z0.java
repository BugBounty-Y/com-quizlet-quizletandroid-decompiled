package androidx.compose.foundation;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class z0 implements InterfaceC0371k0, C0, androidx.compose.ui.graphics.V {
    public static final z0 b = new z0(0);
    public static final z0 c = new z0(1);
    public final /* synthetic */ int a;

    public /* synthetic */ z0(int i) {
        this.a = i;
    }

    @Override // androidx.compose.foundation.C0
    public androidx.compose.ui.q a() {
        return androidx.compose.ui.n.b;
    }

    @Override // androidx.compose.foundation.C0
    public Object b(long j, androidx.compose.foundation.gestures.J0 j0, kotlin.coroutines.h hVar) {
        androidx.compose.foundation.gestures.J0 j02 = new androidx.compose.foundation.gestures.J0(j0.m, hVar);
        j02.l = j;
        Object objInvokeSuspend = j02.invokeSuspend(Unit.a);
        return objInvokeSuspend == kotlin.coroutines.intrinsics.a.a ? objInvokeSuspend : Unit.a;
    }

    @Override // androidx.compose.foundation.InterfaceC0371k0
    public void c(androidx.compose.ui.node.G g) {
        g.b();
    }

    @Override // androidx.compose.foundation.C0
    public boolean d() {
        return false;
    }

    @Override // androidx.compose.ui.graphics.V
    public androidx.compose.ui.graphics.N e(long j, androidx.compose.ui.unit.k kVar, androidx.compose.ui.unit.b bVar) {
        switch (this.a) {
            case 3:
                float fM0 = bVar.m0(G.a);
                return new androidx.compose.ui.graphics.L(new androidx.compose.ui.geometry.c(DefinitionKt.NO_Float_VALUE, -fM0, androidx.compose.ui.geometry.e.d(j), androidx.compose.ui.geometry.e.b(j) + fM0));
            default:
                float fM02 = bVar.m0(G.a);
                return new androidx.compose.ui.graphics.L(new androidx.compose.ui.geometry.c(-fM02, DefinitionKt.NO_Float_VALUE, androidx.compose.ui.geometry.e.d(j) + fM02, androidx.compose.ui.geometry.e.b(j)));
        }
    }

    @Override // androidx.compose.foundation.C0
    public long f(long j, int i, androidx.camera.lifecycle.f fVar) {
        fVar.getClass();
        androidx.compose.foundation.gestures.L0 l0 = (androidx.compose.foundation.gestures.L0) fVar.b;
        return new androidx.compose.ui.geometry.b(androidx.compose.foundation.gestures.L0.a(l0, l0.h, j, l0.g)).a;
    }
}
