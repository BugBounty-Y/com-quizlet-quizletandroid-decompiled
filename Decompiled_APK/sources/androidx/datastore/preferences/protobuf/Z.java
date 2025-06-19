package androidx.datastore.preferences.protobuf;

/* loaded from: classes.dex */
public abstract class Z {
    public abstract a0 a(Object obj);

    public final boolean b(int i, C1103j c1103j, Object obj) throws InvalidProtocolBufferException {
        int i2 = c1103j.b;
        int i3 = i2 >>> 3;
        int i4 = i2 & 7;
        if (i4 == 0) {
            c1103j.w(0);
            ((a0) obj).c(i3 << 3, Long.valueOf(c1103j.a.t()));
            return true;
        }
        if (i4 == 1) {
            c1103j.w(1);
            ((a0) obj).c((i3 << 3) | 1, Long.valueOf(c1103j.a.q()));
            return true;
        }
        if (i4 == 2) {
            ((a0) obj).c((i3 << 3) | 2, c1103j.e());
            return true;
        }
        if (i4 != 3) {
            if (i4 == 4) {
                return false;
            }
            if (i4 != 5) {
                throw InvalidProtocolBufferException.b();
            }
            c1103j.w(5);
            ((a0) obj).c(5 | (i3 << 3), Integer.valueOf(c1103j.a.p()));
            return true;
        }
        a0 a0Var = new a0(0, new int[8], new Object[8], true);
        int i5 = i3 << 3;
        int i6 = i5 | 4;
        int i7 = i + 1;
        if (i7 >= 100) {
            throw new InvalidProtocolBufferException("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        while (c1103j.a() != Integer.MAX_VALUE && b(i7, c1103j, a0Var)) {
        }
        if (i6 != c1103j.b) {
            throw new InvalidProtocolBufferException("Protocol message end-group tag did not match expected tag.");
        }
        if (a0Var.e) {
            a0Var.e = false;
        }
        ((a0) obj).c(i5 | 3, a0Var);
        return true;
    }
}
