package com.google.android.gms.internal.ads;

import java.util.logging.Level;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public abstract class HA extends AbstractC2457os {
    public static final Logger c = Logger.getLogger(HA.class.getName());
    public static final boolean d = AbstractC2906zB.e;
    public C2586rt b;

    public static int B(String str) {
        int length;
        try {
            length = BB.c(str);
        } catch (AB unused) {
            length = str.getBytes(WA.a).length;
        }
        return C(length) + length;
    }

    public static int C(int i) {
        return (352 - (Integer.numberOfLeadingZeros(i) * 9)) >>> 6;
    }

    public static int D(long j) {
        return (640 - (Long.numberOfLeadingZeros(j) * 9)) >>> 6;
    }

    public final void E(String str, AB ab) throws zzgxu {
        c.logp(Level.WARNING, "com.google.protobuf.CodedOutputStream", "inefficientWriteStringNoTag", "Converting ill-formed UTF-16. Your Protocol Buffer will not round trip correctly!", (Throwable) ab);
        byte[] bytes = str.getBytes(WA.a);
        try {
            int length = bytes.length;
            S(length);
            h(0, bytes, length);
        } catch (IndexOutOfBoundsException e) {
            throw new zzgxu(e);
        }
    }

    public abstract void F(byte b);

    public abstract void G(int i, boolean z);

    public abstract void H(int i, BA ba);

    public abstract void I(int i, int i2);

    public abstract void J(int i);

    public abstract void K(int i, long j);

    public abstract void L(long j);

    public abstract void M(int i, int i2);

    public abstract void N(int i);

    public abstract void O(int i, AbstractC2647tA abstractC2647tA, InterfaceC2562rB interfaceC2562rB);

    public abstract void P(int i, String str);

    public abstract void Q(int i, int i2);

    public abstract void R(int i, int i2);

    public abstract void S(int i);

    public abstract void T(int i, long j);

    public abstract void U(long j);
}
