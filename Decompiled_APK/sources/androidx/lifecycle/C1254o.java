package androidx.lifecycle;

import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.lifecycle.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1254o implements InterfaceC5002j {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C1254o(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) throws Throwable {
        switch (this.a) {
            case 0:
                Object objS = ((kotlinx.coroutines.channels.t) ((kotlinx.coroutines.channels.u) this.b)).d.s(obj, hVar);
                if (objS != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            default:
                V v = (V) this.b;
                v.getClass();
                Object objJ = kotlinx.coroutines.E.J(v.b, new U(v, obj, null), hVar);
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                if (objJ != aVar) {
                    objJ = Unit.a;
                }
                if (objJ != aVar) {
                    break;
                }
                break;
        }
        return Unit.a;
    }
}
