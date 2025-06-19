package kotlinx.coroutines;

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Unit;

/* renamed from: kotlinx.coroutines.k0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public class C5027k0 extends q0 implements InterfaceC5034s {
    public final boolean c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5027k0(InterfaceC5025j0 interfaceC5025j0) {
        super(true);
        boolean z = true;
        R(interfaceC5025j0);
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = q0.b;
        InterfaceC5031o interfaceC5031o = (InterfaceC5031o) atomicReferenceFieldUpdater.get(this);
        C5032p c5032p = interfaceC5031o instanceof C5032p ? (C5032p) interfaceC5031o : null;
        if (c5032p == null) {
            z = false;
            break;
        }
        q0 q0VarI = c5032p.i();
        while (!q0VarI.K()) {
            InterfaceC5031o interfaceC5031o2 = (InterfaceC5031o) atomicReferenceFieldUpdater.get(q0VarI);
            C5032p c5032p2 = interfaceC5031o2 instanceof C5032p ? (C5032p) interfaceC5031o2 : null;
            if (c5032p2 == null) {
                z = false;
                break;
            }
            q0VarI = c5032p2.i();
        }
        this.c = z;
    }

    @Override // kotlinx.coroutines.q0
    public final boolean K() {
        return this.c;
    }

    @Override // kotlinx.coroutines.q0
    public final boolean L() {
        return true;
    }

    public final boolean k0() {
        return U(Unit.a);
    }
}
