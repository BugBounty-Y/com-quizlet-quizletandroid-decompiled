package androidx.glance.appwidget.protobuf;

import java.util.Arrays;

/* loaded from: classes.dex */
public final class S {
    public static final S f = new S(0, new int[0], new Object[0], false);
    public int a;
    public int[] b;
    public Object[] c;
    public int d = -1;
    public boolean e;

    public S(int i, int[] iArr, Object[] objArr, boolean z) {
        this.a = i;
        this.b = iArr;
        this.c = objArr;
        this.e = z;
    }

    public final void a(int i) {
        int[] iArr = this.b;
        if (i > iArr.length) {
            int i2 = this.a;
            int i3 = (i2 / 2) + i2;
            if (i3 >= i) {
                i = i3;
            }
            if (i < 8) {
                i = 8;
            }
            this.b = Arrays.copyOf(iArr, i);
            this.c = Arrays.copyOf(this.c, i);
        }
    }

    public final int b() {
        int iJ;
        int iL;
        int iJ2;
        int i = this.d;
        if (i != -1) {
            return i;
        }
        int i2 = 0;
        for (int i3 = 0; i3 < this.a; i3++) {
            int i4 = this.b[i3];
            int i5 = i4 >>> 3;
            int i6 = i4 & 7;
            if (i6 != 0) {
                if (i6 == 1) {
                    ((Long) this.c[i3]).getClass();
                    iJ2 = C1198j.j(i5) + 8;
                } else if (i6 == 2) {
                    iJ2 = C1198j.h(i5, (C1194f) this.c[i3]);
                } else if (i6 == 3) {
                    iJ = C1198j.j(i5) * 2;
                    iL = ((S) this.c[i3]).b();
                } else {
                    if (i6 != 5) {
                        throw new IllegalStateException(InvalidProtocolBufferException.b());
                    }
                    ((Integer) this.c[i3]).getClass();
                    iJ2 = C1198j.j(i5) + 4;
                }
                i2 = iJ2 + i2;
            } else {
                long jLongValue = ((Long) this.c[i3]).longValue();
                iJ = C1198j.j(i5);
                iL = C1198j.l(jLongValue);
            }
            i2 = iL + iJ + i2;
        }
        this.d = i2;
        return i2;
    }

    public final void c(int i, Object obj) {
        if (!this.e) {
            throw new UnsupportedOperationException();
        }
        a(this.a + 1);
        int[] iArr = this.b;
        int i2 = this.a;
        iArr[i2] = i;
        this.c[i2] = obj;
        this.a = i2 + 1;
    }

    public final void d(A a) {
        if (this.a == 0) {
            return;
        }
        a.getClass();
        for (int i = 0; i < this.a; i++) {
            int i2 = this.b[i];
            Object obj = this.c[i];
            int i3 = i2 >>> 3;
            int i4 = i2 & 7;
            C1198j c1198j = (C1198j) a.a;
            if (i4 == 0) {
                c1198j.C(i3, ((Long) obj).longValue());
            } else if (i4 == 1) {
                c1198j.t(i3, ((Long) obj).longValue());
            } else if (i4 == 2) {
                c1198j.q(i3, (C1194f) obj);
            } else if (i4 == 3) {
                c1198j.z(i3, 3);
                ((S) obj).d(a);
                c1198j.z(i3, 4);
            } else {
                if (i4 != 5) {
                    throw new RuntimeException(InvalidProtocolBufferException.b());
                }
                c1198j.r(i3, ((Integer) obj).intValue());
            }
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof S)) {
            return false;
        }
        S s = (S) obj;
        int i = this.a;
        if (i == s.a) {
            int[] iArr = this.b;
            int[] iArr2 = s.b;
            int i2 = 0;
            while (true) {
                if (i2 >= i) {
                    Object[] objArr = this.c;
                    Object[] objArr2 = s.c;
                    int i3 = this.a;
                    for (int i4 = 0; i4 < i3; i4++) {
                        if (objArr[i4].equals(objArr2[i4])) {
                        }
                    }
                    return true;
                }
                if (iArr[i2] != iArr2[i2]) {
                    break;
                }
                i2++;
            }
        }
        return false;
    }

    public final int hashCode() {
        int i = this.a;
        int i2 = (527 + i) * 31;
        int[] iArr = this.b;
        int iHashCode = 17;
        int i3 = 17;
        for (int i4 = 0; i4 < i; i4++) {
            i3 = (i3 * 31) + iArr[i4];
        }
        int i5 = (i2 + i3) * 31;
        Object[] objArr = this.c;
        int i6 = this.a;
        for (int i7 = 0; i7 < i6; i7++) {
            iHashCode = (iHashCode * 31) + objArr[i7].hashCode();
        }
        return i5 + iHashCode;
    }
}
