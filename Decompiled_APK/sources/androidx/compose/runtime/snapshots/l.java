package androidx.compose.runtime.snapshots;

import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class l implements Iterable, kotlin.jvm.internal.markers.a {
    public static final l e = new l(0, 0, 0, null);
    public final long a;
    public final long b;
    public final long c;
    public final long[] d;

    public l(long j, long j2, long j3, long[] jArr) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = jArr;
    }

    public final l a(l lVar) {
        l lVarB;
        long[] jArr;
        l lVar2 = e;
        if (lVar == lVar2) {
            return this;
        }
        if (this == lVar2) {
            return lVar2;
        }
        long j = lVar.c;
        long j2 = this.c;
        long[] jArr2 = lVar.d;
        long j3 = lVar.b;
        long j4 = lVar.a;
        if (j == j2 && jArr2 == (jArr = this.d)) {
            return new l(this.a & (~j4), this.b & (~j3), j2, jArr);
        }
        if (jArr2 != null) {
            lVarB = this;
            for (long j5 : jArr2) {
                lVarB = lVarB.b(j5);
            }
        } else {
            lVarB = this;
        }
        long j6 = 0;
        long j7 = lVar.c;
        if (j3 != 0) {
            for (int i = 0; i < 64; i++) {
                if ((j3 & (1 << i)) != 0) {
                    lVarB = lVarB.b(i + j7);
                }
            }
        }
        if (j4 != 0) {
            int i2 = 0;
            while (i2 < 64) {
                if (((1 << i2) & j4) != j6) {
                    lVarB = lVarB.b(i2 + j7 + 64);
                }
                i2++;
                j6 = 0;
            }
        }
        return lVarB;
    }

    public final l b(long j) {
        long[] jArr;
        int iB;
        long[] jArr2;
        long j2 = this.c;
        long j3 = j - j2;
        if (j3 >= 0 && j3 < 64) {
            long j4 = 1 << ((int) j3);
            long j5 = this.b;
            if ((j5 & j4) != 0) {
                return new l(this.a, j5 & (~j4), j2, this.d);
            }
        } else if (j3 >= 64 && j3 < 128) {
            long j6 = 1 << (((int) j3) - 64);
            long j7 = this.a;
            if ((j7 & j6) != 0) {
                return new l(j7 & (~j6), this.b, j2, this.d);
            }
        } else if (j3 < 0 && (jArr = this.d) != null && (iB = r.b(jArr, j)) >= 0) {
            int length = jArr.length;
            int i = length - 1;
            if (i == 0) {
                jArr2 = null;
            } else {
                long[] jArr3 = new long[i];
                if (iB > 0) {
                    C4930v.g(jArr, jArr3, 0, 0, iB);
                }
                if (iB < i) {
                    C4930v.g(jArr, jArr3, iB, iB + 1, length);
                }
                jArr2 = jArr3;
            }
            return new l(this.a, this.b, this.c, jArr2);
        }
        return this;
    }

    public final boolean e(long j) {
        long[] jArr;
        long j2 = j - this.c;
        return (j2 < 0 || j2 >= 64) ? (j2 < 64 || j2 >= 128) ? j2 <= 0 && (jArr = this.d) != null && r.b(jArr, j) >= 0 : ((1 << (((int) j2) + (-64))) & this.a) != 0 : ((1 << ((int) j2)) & this.b) != 0;
    }

    public final l g(l lVar) {
        long j;
        l lVarH;
        l lVarH2 = lVar;
        l lVar2 = e;
        if (lVarH2 == lVar2) {
            return this;
        }
        if (this == lVar2) {
            return lVarH2;
        }
        long j2 = lVarH2.c;
        long j3 = this.c;
        long j4 = this.b;
        long j5 = this.a;
        long[] jArr = lVarH2.d;
        long j6 = lVarH2.b;
        long j7 = lVarH2.a;
        if (j2 == j3) {
            long[] jArr2 = this.d;
            j = j4;
            if (jArr == jArr2) {
                return new l(j5 | j7, j | j6, j3, jArr2);
            }
        } else {
            j = j4;
        }
        int i = 0;
        long[] jArr3 = this.d;
        if (jArr3 == null) {
            if (jArr3 != null) {
                for (long j8 : jArr3) {
                    lVarH2 = lVarH2.h(j8);
                }
            }
            long j9 = this.c;
            if (j != 0) {
                for (int i2 = 0; i2 < 64; i2++) {
                    if (((1 << i2) & j) != 0) {
                        lVarH2 = lVarH2.h(i2 + j9);
                    }
                }
            }
            if (j5 != 0) {
                while (i < 64) {
                    if (((1 << i) & j5) != 0) {
                        lVarH2 = lVarH2.h(i + j9 + 64);
                    }
                    i++;
                }
            }
            return lVarH2;
        }
        if (jArr != null) {
            lVarH = this;
            for (long j10 : jArr) {
                lVarH = lVarH.h(j10);
            }
        } else {
            lVarH = this;
        }
        long j11 = lVarH2.c;
        if (j6 != 0) {
            for (int i3 = 0; i3 < 64; i3++) {
                if (((1 << i3) & j6) != 0) {
                    lVarH = lVarH.h(i3 + j11);
                }
            }
        }
        if (j7 != 0) {
            while (i < 64) {
                if (((1 << i) & j7) != 0) {
                    lVarH = lVarH.h(i + j11 + 64);
                }
                i++;
            }
        }
        return lVarH;
    }

    /* JADX WARN: Removed duplicated region for block: B:59:0x011e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.compose.runtime.snapshots.l h(long r31) {
        /*
            Method dump skipped, instructions count: 357
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.l.h(long):androidx.compose.runtime.snapshots.l");
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        k block = new k(this, null);
        Intrinsics.checkNotNullParameter(block, "block");
        return kotlin.sequences.j.a(block);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString());
        sb.append(" [");
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(this, 10));
        Iterator it2 = iterator();
        while (it2.hasNext()) {
            arrayList.add(String.valueOf(((Number) it2.next()).longValue()));
        }
        StringBuilder sb2 = new StringBuilder();
        sb2.append((CharSequence) "");
        int size = arrayList.size();
        int i = 0;
        for (int i2 = 0; i2 < size; i2++) {
            Object obj = arrayList.get(i2);
            i++;
            if (i > 1) {
                sb2.append((CharSequence) ", ");
            }
            if (obj != null ? obj instanceof CharSequence : true) {
                sb2.append((CharSequence) obj);
            } else if (obj instanceof Character) {
                sb2.append(((Character) obj).charValue());
            } else {
                sb2.append((CharSequence) String.valueOf(obj));
            }
        }
        sb2.append((CharSequence) "");
        sb.append(sb2.toString());
        sb.append(']');
        return sb.toString();
    }
}
