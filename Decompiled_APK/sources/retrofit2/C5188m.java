package retrofit2;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import okhttp3.InterfaceC5075d;

/* renamed from: retrofit2.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5188m extends AbstractC5190o {
    public final /* synthetic */ int d;
    public final InterfaceC5181f e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C5188m(J j, InterfaceC5075d interfaceC5075d, InterfaceC5186k interfaceC5186k, InterfaceC5181f interfaceC5181f, int i) {
        super(j, interfaceC5075d, interfaceC5186k);
        this.d = i;
        this.e = interfaceC5181f;
    }

    @Override // retrofit2.AbstractC5190o
    public final Object a(u uVar, Object[] objArr) {
        switch (this.d) {
            case 0:
                return this.e.j(uVar);
            default:
                InterfaceC5179d interfaceC5179d = (InterfaceC5179d) this.e.j(uVar);
                kotlin.coroutines.h frame = (kotlin.coroutines.h) objArr[objArr.length - 1];
                try {
                    C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
                    c5028l.r();
                    c5028l.u(new C5192q(interfaceC5179d, 2));
                    interfaceC5179d.j(new kotlinx.coroutines.rx3.d(c5028l));
                    Object objQ = c5028l.q();
                    if (objQ != kotlin.coroutines.intrinsics.a.a) {
                        return objQ;
                    }
                    Intrinsics.checkNotNullParameter(frame, "frame");
                    return objQ;
                } catch (Exception e) {
                    S.s(e, frame);
                    return kotlin.coroutines.intrinsics.a.a;
                }
        }
    }
}
