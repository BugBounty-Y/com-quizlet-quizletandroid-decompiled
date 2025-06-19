package androidx.datastore.preferences.protobuf;

import androidx.core.view.AbstractC1047f0;
import androidx.datastore.preferences.protobuf.InvalidProtocolBufferException;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.nio.charset.Charset;

/* renamed from: androidx.datastore.preferences.protobuf.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1103j {
    public final AbstractC1047f0 a;
    public int b;
    public int c;
    public int d = 0;

    public C1103j(AbstractC1047f0 abstractC1047f0) {
        Charset charset = AbstractC1115w.a;
        this.a = abstractC1047f0;
        abstractC1047f0.b = this;
    }

    public final int a() {
        int i = this.d;
        if (i != 0) {
            this.b = i;
            this.d = 0;
        } else {
            this.b = this.a.B();
        }
        int i2 = this.b;
        return (i2 == 0 || i2 == this.c) ? SubsamplingScaleImageView.TILE_SIZE_AUTO : i2 >>> 3;
    }

    public final void b(Object obj, U u, C1106m c1106m) {
        int i = this.c;
        this.c = ((this.b >>> 3) << 3) | 4;
        try {
            u.i(obj, this, c1106m);
            if (this.b == this.c) {
            } else {
                throw new InvalidProtocolBufferException("Failed to parse the message.");
            }
        } finally {
            this.c = i;
        }
    }

    public final void c(Object obj, U u, C1106m c1106m) throws InvalidProtocolBufferException {
        AbstractC1047f0 abstractC1047f0 = this.a;
        int iC = abstractC1047f0.C();
        if (abstractC1047f0.a >= 100) {
            throw new InvalidProtocolBufferException("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        int i = abstractC1047f0.i(iC);
        abstractC1047f0.a++;
        u.i(obj, this, c1106m);
        abstractC1047f0.a(0);
        abstractC1047f0.a--;
        abstractC1047f0.h(i);
    }

    public final void d(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((S) interfaceC1114v).add(Boolean.valueOf(abstractC1047f0.j()));
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB = abstractC1047f0.B();
                }
            } while (iB == this.b);
            this.d = iB;
            return;
        }
        if (i != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iB2 = abstractC1047f0.b() + abstractC1047f0.C();
        do {
            ((S) interfaceC1114v).add(Boolean.valueOf(abstractC1047f0.j()));
        } while (abstractC1047f0.b() < iB2);
        v(iB2);
    }

    public final C1100g e() throws InvalidProtocolBufferException.InvalidWireTypeException {
        w(2);
        return this.a.k();
    }

    public final void f(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException.InvalidWireTypeException {
        int iB;
        if ((this.b & 7) != 2) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            ((S) interfaceC1114v).add(e());
            AbstractC1047f0 abstractC1047f0 = this.a;
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == this.b);
        this.d = iB;
    }

    public final void g(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 1) {
            do {
                ((S) interfaceC1114v).add(Double.valueOf(abstractC1047f0.n()));
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB = abstractC1047f0.B();
                }
            } while (iB == this.b);
            this.d = iB;
            return;
        }
        if (i != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iC = abstractC1047f0.C();
        if ((iC & 7) != 0) {
            throw new InvalidProtocolBufferException("Failed to parse the message.");
        }
        int iB2 = abstractC1047f0.b() + iC;
        do {
            ((S) interfaceC1114v).add(Double.valueOf(abstractC1047f0.n()));
        } while (abstractC1047f0.b() < iB2);
    }

    public final void h(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((S) interfaceC1114v).add(Integer.valueOf(abstractC1047f0.o()));
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB = abstractC1047f0.B();
                }
            } while (iB == this.b);
            this.d = iB;
            return;
        }
        if (i != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iB2 = abstractC1047f0.b() + abstractC1047f0.C();
        do {
            ((S) interfaceC1114v).add(Integer.valueOf(abstractC1047f0.o()));
        } while (abstractC1047f0.b() < iB2);
        v(iB2);
    }

    public final Object i(o0 o0Var, Class cls, C1106m c1106m) throws InvalidProtocolBufferException {
        int iOrdinal = o0Var.ordinal();
        AbstractC1047f0 abstractC1047f0 = this.a;
        switch (iOrdinal) {
            case 0:
                w(1);
                return Double.valueOf(abstractC1047f0.n());
            case 1:
                w(5);
                return Float.valueOf(abstractC1047f0.r());
            case 2:
                w(0);
                return Long.valueOf(abstractC1047f0.t());
            case 3:
                w(0);
                return Long.valueOf(abstractC1047f0.D());
            case 4:
                w(0);
                return Integer.valueOf(abstractC1047f0.s());
            case 5:
                w(1);
                return Long.valueOf(abstractC1047f0.q());
            case 6:
                w(5);
                return Integer.valueOf(abstractC1047f0.p());
            case 7:
                w(0);
                return Boolean.valueOf(abstractC1047f0.j());
            case 8:
                w(2);
                return abstractC1047f0.A();
            case 9:
            default:
                throw new IllegalArgumentException("unsupported field type.");
            case 10:
                w(2);
                U uA = Q.c.a(cls);
                AbstractC1113u abstractC1113uD = uA.d();
                c(abstractC1113uD, uA, c1106m);
                uA.b(abstractC1113uD);
                return abstractC1113uD;
            case 11:
                return e();
            case 12:
                w(0);
                return Integer.valueOf(abstractC1047f0.C());
            case 13:
                w(0);
                return Integer.valueOf(abstractC1047f0.o());
            case 14:
                w(5);
                return Integer.valueOf(abstractC1047f0.u());
            case 15:
                w(1);
                return Long.valueOf(abstractC1047f0.v());
            case 16:
                w(0);
                return Integer.valueOf(abstractC1047f0.x());
            case 17:
                w(0);
                return Long.valueOf(abstractC1047f0.y());
        }
    }

    public final void j(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 2) {
            int iC = abstractC1047f0.C();
            if ((iC & 3) != 0) {
                throw new InvalidProtocolBufferException("Failed to parse the message.");
            }
            int iB2 = abstractC1047f0.b() + iC;
            do {
                ((S) interfaceC1114v).add(Integer.valueOf(abstractC1047f0.p()));
            } while (abstractC1047f0.b() < iB2);
            return;
        }
        if (i != 5) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            ((S) interfaceC1114v).add(Integer.valueOf(abstractC1047f0.p()));
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == this.b);
        this.d = iB;
    }

    public final void k(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 1) {
            do {
                ((S) interfaceC1114v).add(Long.valueOf(abstractC1047f0.q()));
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB = abstractC1047f0.B();
                }
            } while (iB == this.b);
            this.d = iB;
            return;
        }
        if (i != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iC = abstractC1047f0.C();
        if ((iC & 7) != 0) {
            throw new InvalidProtocolBufferException("Failed to parse the message.");
        }
        int iB2 = abstractC1047f0.b() + iC;
        do {
            ((S) interfaceC1114v).add(Long.valueOf(abstractC1047f0.q()));
        } while (abstractC1047f0.b() < iB2);
    }

    public final void l(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 2) {
            int iC = abstractC1047f0.C();
            if ((iC & 3) != 0) {
                throw new InvalidProtocolBufferException("Failed to parse the message.");
            }
            int iB2 = abstractC1047f0.b() + iC;
            do {
                ((S) interfaceC1114v).add(Float.valueOf(abstractC1047f0.r()));
            } while (abstractC1047f0.b() < iB2);
            return;
        }
        if (i != 5) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            ((S) interfaceC1114v).add(Float.valueOf(abstractC1047f0.r()));
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == this.b);
        this.d = iB;
    }

    public final void m(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((S) interfaceC1114v).add(Integer.valueOf(abstractC1047f0.s()));
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB = abstractC1047f0.B();
                }
            } while (iB == this.b);
            this.d = iB;
            return;
        }
        if (i != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iB2 = abstractC1047f0.b() + abstractC1047f0.C();
        do {
            ((S) interfaceC1114v).add(Integer.valueOf(abstractC1047f0.s()));
        } while (abstractC1047f0.b() < iB2);
        v(iB2);
    }

    public final void n(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((S) interfaceC1114v).add(Long.valueOf(abstractC1047f0.t()));
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB = abstractC1047f0.B();
                }
            } while (iB == this.b);
            this.d = iB;
            return;
        }
        if (i != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iB2 = abstractC1047f0.b() + abstractC1047f0.C();
        do {
            ((S) interfaceC1114v).add(Long.valueOf(abstractC1047f0.t()));
        } while (abstractC1047f0.b() < iB2);
        v(iB2);
    }

    public final void o(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 2) {
            int iC = abstractC1047f0.C();
            if ((iC & 3) != 0) {
                throw new InvalidProtocolBufferException("Failed to parse the message.");
            }
            int iB2 = abstractC1047f0.b() + iC;
            do {
                ((S) interfaceC1114v).add(Integer.valueOf(abstractC1047f0.u()));
            } while (abstractC1047f0.b() < iB2);
            return;
        }
        if (i != 5) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            ((S) interfaceC1114v).add(Integer.valueOf(abstractC1047f0.u()));
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == this.b);
        this.d = iB;
    }

    public final void p(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 1) {
            do {
                ((S) interfaceC1114v).add(Long.valueOf(abstractC1047f0.v()));
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB = abstractC1047f0.B();
                }
            } while (iB == this.b);
            this.d = iB;
            return;
        }
        if (i != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iC = abstractC1047f0.C();
        if ((iC & 7) != 0) {
            throw new InvalidProtocolBufferException("Failed to parse the message.");
        }
        int iB2 = abstractC1047f0.b() + iC;
        do {
            ((S) interfaceC1114v).add(Long.valueOf(abstractC1047f0.v()));
        } while (abstractC1047f0.b() < iB2);
    }

    public final void q(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((S) interfaceC1114v).add(Integer.valueOf(abstractC1047f0.x()));
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB = abstractC1047f0.B();
                }
            } while (iB == this.b);
            this.d = iB;
            return;
        }
        if (i != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iB2 = abstractC1047f0.b() + abstractC1047f0.C();
        do {
            ((S) interfaceC1114v).add(Integer.valueOf(abstractC1047f0.x()));
        } while (abstractC1047f0.b() < iB2);
        v(iB2);
    }

    public final void r(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((S) interfaceC1114v).add(Long.valueOf(abstractC1047f0.y()));
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB = abstractC1047f0.B();
                }
            } while (iB == this.b);
            this.d = iB;
            return;
        }
        if (i != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iB2 = abstractC1047f0.b() + abstractC1047f0.C();
        do {
            ((S) interfaceC1114v).add(Long.valueOf(abstractC1047f0.y()));
        } while (abstractC1047f0.b() < iB2);
        v(iB2);
    }

    public final void s(InterfaceC1114v interfaceC1114v, boolean z) throws InvalidProtocolBufferException.InvalidWireTypeException {
        String strZ;
        int iB;
        if ((this.b & 7) != 2) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            AbstractC1047f0 abstractC1047f0 = this.a;
            if (z) {
                w(2);
                strZ = abstractC1047f0.A();
            } else {
                w(2);
                strZ = abstractC1047f0.z();
            }
            ((S) interfaceC1114v).add(strZ);
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == this.b);
        this.d = iB;
    }

    public final void t(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((S) interfaceC1114v).add(Integer.valueOf(abstractC1047f0.C()));
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB = abstractC1047f0.B();
                }
            } while (iB == this.b);
            this.d = iB;
            return;
        }
        if (i != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iB2 = abstractC1047f0.b() + abstractC1047f0.C();
        do {
            ((S) interfaceC1114v).add(Integer.valueOf(abstractC1047f0.C()));
        } while (abstractC1047f0.b() < iB2);
        v(iB2);
    }

    public final void u(InterfaceC1114v interfaceC1114v) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((S) interfaceC1114v).add(Long.valueOf(abstractC1047f0.D()));
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB = abstractC1047f0.B();
                }
            } while (iB == this.b);
            this.d = iB;
            return;
        }
        if (i != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iB2 = abstractC1047f0.b() + abstractC1047f0.C();
        do {
            ((S) interfaceC1114v).add(Long.valueOf(abstractC1047f0.D()));
        } while (abstractC1047f0.b() < iB2);
        v(iB2);
    }

    public final void v(int i) throws InvalidProtocolBufferException {
        if (this.a.b() != i) {
            throw InvalidProtocolBufferException.e();
        }
    }

    public final void w(int i) throws InvalidProtocolBufferException.InvalidWireTypeException {
        if ((this.b & 7) != i) {
            throw InvalidProtocolBufferException.b();
        }
    }

    public final boolean x() {
        int i;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (abstractC1047f0.c() || (i = this.b) == this.c) {
            return false;
        }
        return abstractC1047f0.E(i);
    }
}
