package com.google.protobuf;

/* loaded from: classes2.dex */
public abstract class j0 {
    public abstract k0 a(Object obj);

    public final boolean b(Object obj, C4015i c4015i) throws InvalidProtocolBufferException {
        int i = c4015i.b;
        int i2 = i >>> 3;
        int i3 = i & 7;
        if (i3 == 0) {
            c4015i.w(0);
            ((k0) obj).c(i2 << 3, Long.valueOf(c4015i.a.t()));
            return true;
        }
        if (i3 == 1) {
            c4015i.w(1);
            ((k0) obj).c((i2 << 3) | 1, Long.valueOf(c4015i.a.q()));
            return true;
        }
        if (i3 == 2) {
            ((k0) obj).c((i2 << 3) | 2, c4015i.e());
            return true;
        }
        if (i3 != 3) {
            if (i3 == 4) {
                return false;
            }
            if (i3 != 5) {
                throw InvalidProtocolBufferException.b();
            }
            c4015i.w(5);
            ((k0) obj).c((i2 << 3) | 5, Integer.valueOf(c4015i.a.p()));
            return true;
        }
        k0 k0Var = new k0(0, new int[8], new Object[8], true);
        int i4 = i2 << 3;
        int i5 = i4 | 4;
        while (c4015i.a() != Integer.MAX_VALUE && b(k0Var, c4015i)) {
        }
        if (i5 != c4015i.b) {
            throw new InvalidProtocolBufferException("Protocol message end-group tag did not match expected tag.");
        }
        if (k0Var.e) {
            k0Var.e = false;
        }
        ((k0) obj).c(i4 | 3, k0Var);
        return true;
    }
}
