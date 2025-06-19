package androidx.compose.ui.text.caches;

import androidx.compose.ui.text.font.C0991e;
import androidx.compose.ui.text.font.C0992f;
import java.util.Arrays;
import java.util.ConcurrentModificationException;
import java.util.Map;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public int[] a;
    public Object[] b;
    public int c;

    public final Object a(Object obj) {
        int iC = obj == null ? c() : b(obj.hashCode(), obj);
        if (iC >= 0) {
            return this.b[(iC << 1) + 1];
        }
        return null;
    }

    public final int b(int i, Object obj) {
        int i2 = this.c;
        if (i2 == 0) {
            return -1;
        }
        int iA = a.a(i2, i, this.a);
        if (iA < 0 || Intrinsics.b(obj, this.b[iA << 1])) {
            return iA;
        }
        int i3 = iA + 1;
        while (i3 < i2 && this.a[i3] == i) {
            if (Intrinsics.b(obj, this.b[i3 << 1])) {
                return i3;
            }
            i3++;
        }
        for (int i4 = iA - 1; i4 >= 0 && this.a[i4] == i; i4--) {
            if (Intrinsics.b(obj, this.b[i4 << 1])) {
                return i4;
            }
        }
        return ~i3;
    }

    public final int c() {
        int i = this.c;
        if (i == 0) {
            return -1;
        }
        int iA = a.a(i, 0, this.a);
        if (iA < 0 || this.b[iA << 1] == null) {
            return iA;
        }
        int i2 = iA + 1;
        while (i2 < i && this.a[i2] == 0) {
            if (this.b[i2 << 1] == null) {
                return i2;
            }
            i2++;
        }
        for (int i3 = iA - 1; i3 >= 0 && this.a[i3] == 0; i3--) {
            if (this.b[i3 << 1] == null) {
                return i3;
            }
        }
        return ~i2;
    }

    public final Object d(C0992f c0992f, C0991e c0991e) {
        int iHashCode;
        int iB;
        int i = this.c;
        if (c0992f == null) {
            iB = c();
            iHashCode = 0;
        } else {
            iHashCode = c0992f.hashCode();
            iB = b(iHashCode, c0992f);
        }
        if (iB >= 0) {
            int i2 = (iB << 1) + 1;
            Object[] objArr = this.b;
            Object obj = objArr[i2];
            objArr[i2] = c0991e;
            return obj;
        }
        int i3 = ~iB;
        int[] iArr = this.a;
        if (i >= iArr.length) {
            int i4 = 8;
            if (i >= 8) {
                i4 = (i >> 1) + i;
            } else if (i < 4) {
                i4 = 4;
            }
            int[] iArrCopyOf = Arrays.copyOf(iArr, i4);
            Intrinsics.checkNotNullExpressionValue(iArrCopyOf, "copyOf(this, newSize)");
            this.a = iArrCopyOf;
            Object[] objArrCopyOf = Arrays.copyOf(this.b, i4 << 1);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(this, newSize)");
            this.b = objArrCopyOf;
            if (i != this.c) {
                throw new ConcurrentModificationException();
            }
        }
        if (i3 < i) {
            int[] iArr2 = this.a;
            int i5 = i3 + 1;
            C4930v.e(i5, i3, i, iArr2, iArr2);
            Object[] objArr2 = this.b;
            C4930v.h(objArr2, i5 << 1, objArr2, i3 << 1, this.c << 1);
        }
        int i6 = this.c;
        if (i == i6) {
            int[] iArr3 = this.a;
            if (i3 < iArr3.length) {
                iArr3[i3] = iHashCode;
                Object[] objArr3 = this.b;
                int i7 = i3 << 1;
                objArr3[i7] = c0992f;
                objArr3[i7 + 1] = c0991e;
                this.c = i6 + 1;
                return null;
            }
        }
        throw new ConcurrentModificationException();
    }

    public final boolean equals(Object obj) {
        int i;
        if (this == obj) {
            return true;
        }
        try {
            if (obj instanceof c) {
                c cVar = (c) obj;
                int i2 = this.c;
                if (i2 == cVar.c) {
                    for (int i3 = 0; i3 < i2; i3++) {
                        Object[] objArr = this.b;
                        int i4 = i3 << 1;
                        Object obj2 = objArr[i4];
                        Object obj3 = objArr[i4 + 1];
                        Object objA = cVar.a(obj2);
                        if (obj3 == null) {
                            if (objA == null) {
                                if ((obj2 == null ? cVar.c() : cVar.b(obj2.hashCode(), obj2)) >= 0) {
                                }
                            }
                        } else if (obj3.equals(objA)) {
                        }
                    }
                    return true;
                }
            } else if ((obj instanceof Map) && this.c == ((Map) obj).size()) {
                int i5 = this.c;
                for (0; i < i5; i + 1) {
                    Object[] objArr2 = this.b;
                    int i6 = i << 1;
                    Object obj4 = objArr2[i6];
                    Object obj5 = objArr2[i6 + 1];
                    Object obj6 = ((Map) obj).get(obj4);
                    if (obj5 == null) {
                        i = (obj6 == null && ((Map) obj).containsKey(obj4)) ? i + 1 : 0;
                    } else if (obj5.equals(obj6)) {
                    }
                }
                return true;
            }
        } catch (ClassCastException | NullPointerException unused) {
        }
        return false;
    }

    public final int hashCode() {
        int[] iArr = this.a;
        Object[] objArr = this.b;
        int i = this.c;
        int i2 = 1;
        int i3 = 0;
        int iHashCode = 0;
        while (i3 < i) {
            Object obj = objArr[i2];
            iHashCode += (obj != null ? obj.hashCode() : 0) ^ iArr[i3];
            i3++;
            i2 += 2;
        }
        return iHashCode;
    }

    public final String toString() {
        int i = this.c;
        if (i <= 0) {
            return "{}";
        }
        StringBuilder sb = new StringBuilder(i * 28);
        sb.append('{');
        int i2 = this.c;
        for (int i3 = 0; i3 < i2; i3++) {
            if (i3 > 0) {
                sb.append(", ");
            }
            int i4 = i3 << 1;
            Object obj = this.b[i4];
            if (obj != this) {
                sb.append(obj);
            } else {
                sb.append("(this Map)");
            }
            sb.append('=');
            Object obj2 = this.b[i4 + 1];
            if (obj2 != this) {
                sb.append(obj2);
            } else {
                sb.append("(this Map)");
            }
        }
        sb.append('}');
        return sb.toString();
    }
}
