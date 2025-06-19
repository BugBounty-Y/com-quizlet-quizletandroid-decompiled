package androidx.glance.appwidget.protobuf;

/* loaded from: classes.dex */
public abstract class Q {
    public abstract S a(Object obj);

    public final boolean b(int i, C1197i c1197i, Object obj) throws InvalidProtocolBufferException {
        int i2 = c1197i.b;
        int i3 = i2 >>> 3;
        int i4 = i2 & 7;
        if (i4 == 0) {
            c1197i.v(0);
            ((S) obj).c(i3 << 3, Long.valueOf(c1197i.a.t()));
            return true;
        }
        if (i4 == 1) {
            c1197i.v(1);
            ((S) obj).c((i3 << 3) | 1, Long.valueOf(c1197i.a.q()));
            return true;
        }
        if (i4 == 2) {
            ((S) obj).c((i3 << 3) | 2, c1197i.e());
            return true;
        }
        if (i4 != 3) {
            if (i4 == 4) {
                return false;
            }
            if (i4 != 5) {
                throw InvalidProtocolBufferException.b();
            }
            c1197i.v(5);
            ((S) obj).c(5 | (i3 << 3), Integer.valueOf(c1197i.a.p()));
            return true;
        }
        S s = new S(0, new int[8], new Object[8], true);
        int i5 = i3 << 3;
        int i6 = i5 | 4;
        int i7 = i + 1;
        if (i7 >= 100) {
            throw new InvalidProtocolBufferException("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        while (c1197i.a() != Integer.MAX_VALUE && b(i7, c1197i, s)) {
        }
        if (i6 != c1197i.b) {
            throw new InvalidProtocolBufferException("Protocol message end-group tag did not match expected tag.");
        }
        if (s.e) {
            s.e = false;
        }
        ((S) obj).c(i5 | 3, s);
        return true;
    }
}
