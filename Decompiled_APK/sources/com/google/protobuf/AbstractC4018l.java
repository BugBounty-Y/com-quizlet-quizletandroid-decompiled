package com.google.protobuf;

import java.util.logging.Level;
import java.util.logging.Logger;

/* renamed from: com.google.protobuf.l, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC4018l extends h0 {
    public static final Logger d = Logger.getLogger(AbstractC4018l.class.getName());
    public static final boolean e = t0.e;
    public K c;

    public static int g(int i, C4012f c4012f) {
        return h(c4012f) + j(i);
    }

    public static int h(C4012f c4012f) {
        int size = c4012f.size();
        return k(size) + size;
    }

    public static int i(String str) {
        int length;
        try {
            length = w0.b(str);
        } catch (v0 unused) {
            length = str.getBytes(C.a).length;
        }
        return k(length) + length;
    }

    public static int j(int i) {
        return k(i << 3);
    }

    public static int k(int i) {
        return (352 - (Integer.numberOfLeadingZeros(i) * 9)) >>> 6;
    }

    public static int l(long j) {
        return (640 - (Long.numberOfLeadingZeros(j) * 9)) >>> 6;
    }

    public abstract void A(int i, String str);

    public abstract void B(String str);

    public abstract void C(int i, int i2);

    public abstract void D(int i, int i2);

    public abstract void E(int i);

    public abstract void F(int i, long j);

    public abstract void G(long j);

    public final void m(String str, v0 v0Var) throws CodedOutputStream$OutOfSpaceException {
        d.log(Level.WARNING, "Converting ill-formed UTF-16. Your Protocol Buffer will not round trip correctly!", (Throwable) v0Var);
        byte[] bytes = str.getBytes(C.a);
        try {
            E(bytes.length);
            f(0, bytes, bytes.length);
        } catch (IndexOutOfBoundsException e2) {
            throw new CodedOutputStream$OutOfSpaceException(e2);
        }
    }

    public abstract void n(byte b);

    public abstract void o(int i, boolean z);

    public abstract void p(int i, byte[] bArr);

    public abstract void q(int i, C4012f c4012f);

    public abstract void r(C4012f c4012f);

    public abstract void s(int i, int i2);

    public abstract void t(int i);

    public abstract void u(int i, long j);

    public abstract void v(long j);

    public abstract void w(int i, int i2);

    public abstract void x(int i);

    public abstract void y(int i, AbstractC4004a abstractC4004a, InterfaceC4009c0 interfaceC4009c0);

    public abstract void z(AbstractC4004a abstractC4004a);
}
