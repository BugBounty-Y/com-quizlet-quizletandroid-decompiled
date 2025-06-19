package retrofit2;

import kotlin.jvm.internal.Intrinsics;
import okhttp3.InterfaceC5075d;

/* renamed from: retrofit2.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5189n extends AbstractC5190o {
    public final InterfaceC5181f d;
    public final boolean e;

    public C5189n(J j, InterfaceC5075d interfaceC5075d, InterfaceC5186k interfaceC5186k, InterfaceC5181f interfaceC5181f, boolean z) {
        super(j, interfaceC5075d, interfaceC5186k);
        this.d = interfaceC5181f;
        this.e = z;
    }

    @Override // retrofit2.AbstractC5190o
    public final Object a(u uVar, Object[] objArr) {
        InterfaceC5179d interfaceC5179d = (InterfaceC5179d) this.d.j(uVar);
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) objArr[objArr.length - 1];
        try {
            if (!this.e) {
                return S.b(interfaceC5179d, hVar);
            }
            Intrinsics.e(interfaceC5179d, "null cannot be cast to non-null type retrofit2.Call<kotlin.Unit?>");
            return S.c(interfaceC5179d, hVar);
        } catch (LinkageError e) {
            throw e;
        } catch (ThreadDeath e2) {
            throw e2;
        } catch (VirtualMachineError e3) {
            throw e3;
        } catch (Throwable th) {
            S.s(th, hVar);
            return kotlin.coroutines.intrinsics.a.a;
        }
    }
}
