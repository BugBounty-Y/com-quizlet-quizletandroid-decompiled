package androidx.glance.appwidget.protobuf;

import androidx.core.view.AbstractC1047f0;
import androidx.glance.appwidget.protobuf.InvalidProtocolBufferException;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.nio.charset.Charset;

/* renamed from: androidx.glance.appwidget.protobuf.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1197i {
    public final AbstractC1047f0 a;
    public int b;
    public int c;
    public int d = 0;

    public C1197i(AbstractC1047f0 abstractC1047f0) {
        Charset charset = AbstractC1209v.a;
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

    public final void b(Object obj, O o, C1200l c1200l) {
        int i = this.c;
        this.c = ((this.b >>> 3) << 3) | 4;
        try {
            o.f(obj, this, c1200l);
            if (this.b == this.c) {
            } else {
                throw new InvalidProtocolBufferException("Failed to parse the message.");
            }
        } finally {
            this.c = i;
        }
    }

    public final void c(Object obj, O o, C1200l c1200l) throws InvalidProtocolBufferException {
        AbstractC1047f0 abstractC1047f0 = this.a;
        int iC = abstractC1047f0.C();
        if (abstractC1047f0.a >= 100) {
            throw new InvalidProtocolBufferException("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        int i = abstractC1047f0.i(iC);
        abstractC1047f0.a++;
        o.f(obj, this, c1200l);
        abstractC1047f0.a(0);
        abstractC1047f0.a--;
        abstractC1047f0.h(i);
    }

    public final void d(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((M) interfaceC1208u).add(Boolean.valueOf(abstractC1047f0.j()));
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
            ((M) interfaceC1208u).add(Boolean.valueOf(abstractC1047f0.j()));
        } while (abstractC1047f0.b() < iB2);
        u(iB2);
    }

    public final C1194f e() throws InvalidProtocolBufferException.InvalidWireTypeException {
        v(2);
        return this.a.l();
    }

    public final void f(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException.InvalidWireTypeException {
        int iB;
        if ((this.b & 7) != 2) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            ((M) interfaceC1208u).add(e());
            AbstractC1047f0 abstractC1047f0 = this.a;
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == this.b);
        this.d = iB;
    }

    public final void g(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 1) {
            do {
                ((M) interfaceC1208u).add(Double.valueOf(abstractC1047f0.n()));
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
            ((M) interfaceC1208u).add(Double.valueOf(abstractC1047f0.n()));
        } while (abstractC1047f0.b() < iB2);
    }

    public final void h(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((M) interfaceC1208u).add(Integer.valueOf(abstractC1047f0.o()));
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
            ((M) interfaceC1208u).add(Integer.valueOf(abstractC1047f0.o()));
        } while (abstractC1047f0.b() < iB2);
        u(iB2);
    }

    public final void i(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
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
                ((M) interfaceC1208u).add(Integer.valueOf(abstractC1047f0.p()));
            } while (abstractC1047f0.b() < iB2);
            return;
        }
        if (i != 5) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            ((M) interfaceC1208u).add(Integer.valueOf(abstractC1047f0.p()));
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == this.b);
        this.d = iB;
    }

    public final void j(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 1) {
            do {
                ((M) interfaceC1208u).add(Long.valueOf(abstractC1047f0.q()));
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
            ((M) interfaceC1208u).add(Long.valueOf(abstractC1047f0.q()));
        } while (abstractC1047f0.b() < iB2);
    }

    public final void k(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
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
                ((M) interfaceC1208u).add(Float.valueOf(abstractC1047f0.r()));
            } while (abstractC1047f0.b() < iB2);
            return;
        }
        if (i != 5) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            ((M) interfaceC1208u).add(Float.valueOf(abstractC1047f0.r()));
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == this.b);
        this.d = iB;
    }

    public final void l(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((M) interfaceC1208u).add(Integer.valueOf(abstractC1047f0.s()));
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
            ((M) interfaceC1208u).add(Integer.valueOf(abstractC1047f0.s()));
        } while (abstractC1047f0.b() < iB2);
        u(iB2);
    }

    public final void m(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((M) interfaceC1208u).add(Long.valueOf(abstractC1047f0.t()));
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
            ((M) interfaceC1208u).add(Long.valueOf(abstractC1047f0.t()));
        } while (abstractC1047f0.b() < iB2);
        u(iB2);
    }

    public final void n(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
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
                ((M) interfaceC1208u).add(Integer.valueOf(abstractC1047f0.u()));
            } while (abstractC1047f0.b() < iB2);
            return;
        }
        if (i != 5) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            ((M) interfaceC1208u).add(Integer.valueOf(abstractC1047f0.u()));
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == this.b);
        this.d = iB;
    }

    public final void o(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 1) {
            do {
                ((M) interfaceC1208u).add(Long.valueOf(abstractC1047f0.v()));
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
            ((M) interfaceC1208u).add(Long.valueOf(abstractC1047f0.v()));
        } while (abstractC1047f0.b() < iB2);
    }

    public final void p(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((M) interfaceC1208u).add(Integer.valueOf(abstractC1047f0.x()));
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
            ((M) interfaceC1208u).add(Integer.valueOf(abstractC1047f0.x()));
        } while (abstractC1047f0.b() < iB2);
        u(iB2);
    }

    public final void q(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((M) interfaceC1208u).add(Long.valueOf(abstractC1047f0.y()));
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
            ((M) interfaceC1208u).add(Long.valueOf(abstractC1047f0.y()));
        } while (abstractC1047f0.b() < iB2);
        u(iB2);
    }

    public final void r(InterfaceC1208u interfaceC1208u, boolean z) throws InvalidProtocolBufferException.InvalidWireTypeException {
        String strZ;
        int iB;
        if ((this.b & 7) != 2) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            AbstractC1047f0 abstractC1047f0 = this.a;
            if (z) {
                v(2);
                strZ = abstractC1047f0.A();
            } else {
                v(2);
                strZ = abstractC1047f0.z();
            }
            ((M) interfaceC1208u).add(strZ);
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == this.b);
        this.d = iB;
    }

    public final void s(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((M) interfaceC1208u).add(Integer.valueOf(abstractC1047f0.C()));
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
            ((M) interfaceC1208u).add(Integer.valueOf(abstractC1047f0.C()));
        } while (abstractC1047f0.b() < iB2);
        u(iB2);
    }

    public final void t(InterfaceC1208u interfaceC1208u) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                ((M) interfaceC1208u).add(Long.valueOf(abstractC1047f0.D()));
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
            ((M) interfaceC1208u).add(Long.valueOf(abstractC1047f0.D()));
        } while (abstractC1047f0.b() < iB2);
        u(iB2);
    }

    public final void u(int i) throws InvalidProtocolBufferException {
        if (this.a.b() != i) {
            throw InvalidProtocolBufferException.e();
        }
    }

    public final void v(int i) throws InvalidProtocolBufferException.InvalidWireTypeException {
        if ((this.b & 7) != i) {
            throw InvalidProtocolBufferException.b();
        }
    }
}
