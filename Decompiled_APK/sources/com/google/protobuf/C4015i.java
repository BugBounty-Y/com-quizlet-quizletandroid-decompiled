package com.google.protobuf;

import androidx.core.view.AbstractC1047f0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.protobuf.InvalidProtocolBufferException;
import java.nio.charset.Charset;
import java.util.List;

/* renamed from: com.google.protobuf.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4015i {
    public final AbstractC1047f0 a;
    public int b;
    public int c;
    public int d = 0;

    public C4015i(AbstractC1047f0 abstractC1047f0) {
        Charset charset = C.a;
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

    public final void b(Object obj, InterfaceC4009c0 interfaceC4009c0, C4020n c4020n) {
        int i = this.c;
        this.c = ((this.b >>> 3) << 3) | 4;
        try {
            interfaceC4009c0.f(obj, this, c4020n);
            if (this.b == this.c) {
            } else {
                throw new InvalidProtocolBufferException("Failed to parse the message.");
            }
        } finally {
            this.c = i;
        }
    }

    public final void c(Object obj, InterfaceC4009c0 interfaceC4009c0, C4020n c4020n) throws InvalidProtocolBufferException {
        AbstractC1047f0 abstractC1047f0 = this.a;
        int iC = abstractC1047f0.C();
        if (abstractC1047f0.a >= 100) {
            throw new InvalidProtocolBufferException("Protocol message had too many levels of nesting.  May be malicious.  Use CodedInputStream.setRecursionLimit() to increase the depth limit.");
        }
        int i = abstractC1047f0.i(iC);
        abstractC1047f0.a++;
        interfaceC4009c0.f(obj, this, c4020n);
        abstractC1047f0.a(0);
        abstractC1047f0.a--;
        abstractC1047f0.h(i);
    }

    public final void d(List list) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                list.add(Boolean.valueOf(abstractC1047f0.j()));
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
            list.add(Boolean.valueOf(abstractC1047f0.j()));
        } while (abstractC1047f0.b() < iB2);
        v(iB2);
    }

    public final C4012f e() throws InvalidProtocolBufferException.InvalidWireTypeException {
        w(2);
        return this.a.m();
    }

    public final void f(List list) throws InvalidProtocolBufferException.InvalidWireTypeException {
        int iB;
        if ((this.b & 7) != 2) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            list.add(e());
            AbstractC1047f0 abstractC1047f0 = this.a;
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == this.b);
        this.d = iB;
    }

    public final void g(List list) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 1) {
            do {
                list.add(Double.valueOf(abstractC1047f0.n()));
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
            list.add(Double.valueOf(abstractC1047f0.n()));
        } while (abstractC1047f0.b() < iB2);
    }

    public final void h(List list) throws InvalidProtocolBufferException {
        int iB;
        int iB2;
        boolean z = list instanceof C4028w;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (!z) {
            int i = this.b & 7;
            if (i == 0) {
                do {
                    list.add(Integer.valueOf(abstractC1047f0.o()));
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
            int iB3 = abstractC1047f0.b() + abstractC1047f0.C();
            do {
                list.add(Integer.valueOf(abstractC1047f0.o()));
            } while (abstractC1047f0.b() < iB3);
            v(iB3);
            return;
        }
        C4028w c4028w = (C4028w) list;
        int i2 = this.b & 7;
        if (i2 == 0) {
            do {
                c4028w.b(abstractC1047f0.o());
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB2 = abstractC1047f0.B();
                }
            } while (iB2 == this.b);
            this.d = iB2;
            return;
        }
        if (i2 != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iB4 = abstractC1047f0.b() + abstractC1047f0.C();
        do {
            c4028w.b(abstractC1047f0.o());
        } while (abstractC1047f0.b() < iB4);
        v(iB4);
    }

    public final Object i(B0 b0, Class cls, C4020n c4020n) throws InvalidProtocolBufferException {
        int iOrdinal = b0.ordinal();
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
                InterfaceC4009c0 interfaceC4009c0A = Z.c.a(cls);
                AbstractC4027v abstractC4027vD = interfaceC4009c0A.d();
                c(abstractC4027vD, interfaceC4009c0A, c4020n);
                interfaceC4009c0A.b(abstractC4027vD);
                return abstractC4027vD;
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

    public final void j(List list) throws InvalidProtocolBufferException {
        int iB;
        int iB2;
        boolean z = list instanceof C4028w;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (!z) {
            int i = this.b & 7;
            if (i == 2) {
                int iC = abstractC1047f0.C();
                if ((iC & 3) != 0) {
                    throw new InvalidProtocolBufferException("Failed to parse the message.");
                }
                int iB3 = iC + abstractC1047f0.b();
                do {
                    list.add(Integer.valueOf(abstractC1047f0.p()));
                } while (abstractC1047f0.b() < iB3);
                return;
            }
            if (i != 5) {
                throw InvalidProtocolBufferException.b();
            }
            do {
                list.add(Integer.valueOf(abstractC1047f0.p()));
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB = abstractC1047f0.B();
                }
            } while (iB == this.b);
            this.d = iB;
            return;
        }
        C4028w c4028w = (C4028w) list;
        int i2 = this.b & 7;
        if (i2 == 2) {
            int iC2 = abstractC1047f0.C();
            if ((iC2 & 3) != 0) {
                throw new InvalidProtocolBufferException("Failed to parse the message.");
            }
            int iB4 = iC2 + abstractC1047f0.b();
            do {
                c4028w.b(abstractC1047f0.p());
            } while (abstractC1047f0.b() < iB4);
            return;
        }
        if (i2 != 5) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            c4028w.b(abstractC1047f0.p());
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB2 = abstractC1047f0.B();
            }
        } while (iB2 == this.b);
        this.d = iB2;
    }

    public final void k(List list) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 1) {
            do {
                list.add(Long.valueOf(abstractC1047f0.q()));
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
            list.add(Long.valueOf(abstractC1047f0.q()));
        } while (abstractC1047f0.b() < iB2);
    }

    public final void l(List list) throws InvalidProtocolBufferException {
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
                list.add(Float.valueOf(abstractC1047f0.r()));
            } while (abstractC1047f0.b() < iB2);
            return;
        }
        if (i != 5) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            list.add(Float.valueOf(abstractC1047f0.r()));
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == this.b);
        this.d = iB;
    }

    public final void m(List list) throws InvalidProtocolBufferException {
        int iB;
        int iB2;
        boolean z = list instanceof C4028w;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (!z) {
            int i = this.b & 7;
            if (i == 0) {
                do {
                    list.add(Integer.valueOf(abstractC1047f0.s()));
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
            int iB3 = abstractC1047f0.b() + abstractC1047f0.C();
            do {
                list.add(Integer.valueOf(abstractC1047f0.s()));
            } while (abstractC1047f0.b() < iB3);
            v(iB3);
            return;
        }
        C4028w c4028w = (C4028w) list;
        int i2 = this.b & 7;
        if (i2 == 0) {
            do {
                c4028w.b(abstractC1047f0.s());
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB2 = abstractC1047f0.B();
                }
            } while (iB2 == this.b);
            this.d = iB2;
            return;
        }
        if (i2 != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iB4 = abstractC1047f0.b() + abstractC1047f0.C();
        do {
            c4028w.b(abstractC1047f0.s());
        } while (abstractC1047f0.b() < iB4);
        v(iB4);
    }

    public final void n(List list) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                list.add(Long.valueOf(abstractC1047f0.t()));
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
            list.add(Long.valueOf(abstractC1047f0.t()));
        } while (abstractC1047f0.b() < iB2);
        v(iB2);
    }

    public final void o(List list) throws InvalidProtocolBufferException {
        int iB;
        int iB2;
        boolean z = list instanceof C4028w;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (!z) {
            int i = this.b & 7;
            if (i == 2) {
                int iC = abstractC1047f0.C();
                if ((iC & 3) != 0) {
                    throw new InvalidProtocolBufferException("Failed to parse the message.");
                }
                int iB3 = iC + abstractC1047f0.b();
                do {
                    list.add(Integer.valueOf(abstractC1047f0.u()));
                } while (abstractC1047f0.b() < iB3);
                return;
            }
            if (i != 5) {
                throw InvalidProtocolBufferException.b();
            }
            do {
                list.add(Integer.valueOf(abstractC1047f0.u()));
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB = abstractC1047f0.B();
                }
            } while (iB == this.b);
            this.d = iB;
            return;
        }
        C4028w c4028w = (C4028w) list;
        int i2 = this.b & 7;
        if (i2 == 2) {
            int iC2 = abstractC1047f0.C();
            if ((iC2 & 3) != 0) {
                throw new InvalidProtocolBufferException("Failed to parse the message.");
            }
            int iB4 = iC2 + abstractC1047f0.b();
            do {
                c4028w.b(abstractC1047f0.u());
            } while (abstractC1047f0.b() < iB4);
            return;
        }
        if (i2 != 5) {
            throw InvalidProtocolBufferException.b();
        }
        do {
            c4028w.b(abstractC1047f0.u());
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB2 = abstractC1047f0.B();
            }
        } while (iB2 == this.b);
        this.d = iB2;
    }

    public final void p(List list) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 1) {
            do {
                list.add(Long.valueOf(abstractC1047f0.v()));
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
            list.add(Long.valueOf(abstractC1047f0.v()));
        } while (abstractC1047f0.b() < iB2);
    }

    public final void q(List list) throws InvalidProtocolBufferException {
        int iB;
        int iB2;
        boolean z = list instanceof C4028w;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (!z) {
            int i = this.b & 7;
            if (i == 0) {
                do {
                    list.add(Integer.valueOf(abstractC1047f0.x()));
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
            int iB3 = abstractC1047f0.b() + abstractC1047f0.C();
            do {
                list.add(Integer.valueOf(abstractC1047f0.x()));
            } while (abstractC1047f0.b() < iB3);
            v(iB3);
            return;
        }
        C4028w c4028w = (C4028w) list;
        int i2 = this.b & 7;
        if (i2 == 0) {
            do {
                c4028w.b(abstractC1047f0.x());
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB2 = abstractC1047f0.B();
                }
            } while (iB2 == this.b);
            this.d = iB2;
            return;
        }
        if (i2 != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iB4 = abstractC1047f0.b() + abstractC1047f0.C();
        do {
            c4028w.b(abstractC1047f0.x());
        } while (abstractC1047f0.b() < iB4);
        v(iB4);
    }

    public final void r(List list) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                list.add(Long.valueOf(abstractC1047f0.y()));
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
            list.add(Long.valueOf(abstractC1047f0.y()));
        } while (abstractC1047f0.b() < iB2);
        v(iB2);
    }

    public final void s(List list, boolean z) throws InvalidProtocolBufferException.InvalidWireTypeException {
        String strZ;
        int iB;
        int iB2;
        if ((this.b & 7) != 2) {
            throw InvalidProtocolBufferException.b();
        }
        boolean z2 = list instanceof F;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (z2 && !z) {
            F f = (F) list;
            do {
                f.p(e());
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB2 = abstractC1047f0.B();
                }
            } while (iB2 == this.b);
            this.d = iB2;
            return;
        }
        do {
            if (z) {
                w(2);
                strZ = abstractC1047f0.A();
            } else {
                w(2);
                strZ = abstractC1047f0.z();
            }
            list.add(strZ);
            if (abstractC1047f0.c()) {
                return;
            } else {
                iB = abstractC1047f0.B();
            }
        } while (iB == this.b);
        this.d = iB;
    }

    public final void t(List list) throws InvalidProtocolBufferException {
        int iB;
        int iB2;
        boolean z = list instanceof C4028w;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (!z) {
            int i = this.b & 7;
            if (i == 0) {
                do {
                    list.add(Integer.valueOf(abstractC1047f0.C()));
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
            int iB3 = abstractC1047f0.b() + abstractC1047f0.C();
            do {
                list.add(Integer.valueOf(abstractC1047f0.C()));
            } while (abstractC1047f0.b() < iB3);
            v(iB3);
            return;
        }
        C4028w c4028w = (C4028w) list;
        int i2 = this.b & 7;
        if (i2 == 0) {
            do {
                c4028w.b(abstractC1047f0.C());
                if (abstractC1047f0.c()) {
                    return;
                } else {
                    iB2 = abstractC1047f0.B();
                }
            } while (iB2 == this.b);
            this.d = iB2;
            return;
        }
        if (i2 != 2) {
            throw InvalidProtocolBufferException.b();
        }
        int iB4 = abstractC1047f0.b() + abstractC1047f0.C();
        do {
            c4028w.b(abstractC1047f0.C());
        } while (abstractC1047f0.b() < iB4);
        v(iB4);
    }

    public final void u(List list) throws InvalidProtocolBufferException {
        int iB;
        int i = this.b & 7;
        AbstractC1047f0 abstractC1047f0 = this.a;
        if (i == 0) {
            do {
                list.add(Long.valueOf(abstractC1047f0.D()));
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
            list.add(Long.valueOf(abstractC1047f0.D()));
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
