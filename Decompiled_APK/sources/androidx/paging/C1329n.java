package androidx.paging;

import androidx.datastore.core.C1086s;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.paging.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1329n implements InterfaceC4992i {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlinx.coroutines.flow.s0 b;

    public /* synthetic */ C1329n(kotlinx.coroutines.flow.s0 s0Var, int i) {
        this.a = i;
        this.b = s0Var;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) throws Throwable {
        switch (this.a) {
            case 0:
                this.b.b(new C1086s(interfaceC5002j, 2), hVar);
                break;
            case 1:
                this.b.b(new C1086s(interfaceC5002j, 7), hVar);
                break;
            default:
                this.b.b(new C1086s(interfaceC5002j, 12), hVar);
                break;
        }
        return kotlin.coroutines.intrinsics.a.a;
    }
}
