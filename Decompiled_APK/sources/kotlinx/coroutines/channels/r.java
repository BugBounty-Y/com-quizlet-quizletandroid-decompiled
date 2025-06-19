package kotlinx.coroutines.channels;

import androidx.camera.camera2.internal.AbstractC0147y;
import kotlin.Unit;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.J0;

/* loaded from: classes3.dex */
public final class r extends h {
    public final a k;

    public r(int i, a aVar) {
        super(i);
        this.k = aVar;
        if (aVar != a.a) {
            if (i < 1) {
                throw new IllegalArgumentException(AbstractC0147y.c(i, "Buffered channel capacity must be at least 1, but ", " was specified").toString());
            }
        } else {
            throw new IllegalArgumentException(("This implementation does not support suspension for senders, use " + K.a(h.class).f() + " instead").toString());
        }
    }

    @Override // kotlinx.coroutines.channels.h
    public final boolean A() {
        return this.k == a.b;
    }

    public final Object M(Object obj, boolean z) {
        p pVar;
        r rVar;
        Object obj2;
        if (this.k == a.c) {
            Object objO = super.o(obj);
            return (!(objO instanceof n) || (objO instanceof m)) ? objO : Unit.a;
        }
        Object obj3 = j.d;
        p pVar2 = (p) h.f.get(this);
        while (true) {
            long andIncrement = h.b.getAndIncrement(this);
            long j = andIncrement & 1152921504606846975L;
            boolean zX = x(andIncrement, false);
            int i = j.b;
            long j2 = i;
            long j3 = j / j2;
            int i2 = (int) (j % j2);
            if (pVar2.c != j3) {
                p pVarA = h.a(this, j3, pVar2);
                if (pVarA != null) {
                    pVar = pVarA;
                    obj2 = obj;
                    rVar = this;
                } else if (zX) {
                    return new m(u());
                }
            } else {
                pVar = pVar2;
                rVar = this;
                obj2 = obj;
            }
            int iD = h.d(rVar, pVar, i2, obj2, j, obj3, zX);
            pVar2 = pVar;
            if (iD == 0) {
                pVar2.a();
                return Unit.a;
            }
            if (iD == 1) {
                return Unit.a;
            }
            if (iD == 2) {
                if (zX) {
                    pVar2.i();
                    return new m(u());
                }
                J0 j0 = obj3 instanceof J0 ? (J0) obj3 : null;
                if (j0 != null) {
                    j0.a(pVar2, i2 + i);
                }
                m((pVar2.c * j2) + i2);
                return Unit.a;
            }
            if (iD == 3) {
                throw new IllegalStateException("unexpected");
            }
            if (iD == 4) {
                if (j < h.c.get(this)) {
                    pVar2.a();
                }
                return new m(u());
            }
            if (iD == 5) {
                pVar2.a();
            }
            obj = obj2;
        }
    }

    @Override // kotlinx.coroutines.channels.h, kotlinx.coroutines.channels.x
    public final Object o(Object obj) {
        return M(obj, false);
    }

    @Override // kotlinx.coroutines.channels.h, kotlinx.coroutines.channels.x
    public final Object s(Object obj, kotlin.coroutines.h hVar) throws Throwable {
        Object objM = M(obj, true);
        if (!(objM instanceof m)) {
            return Unit.a;
        }
        o.a(objM);
        throw u();
    }
}
