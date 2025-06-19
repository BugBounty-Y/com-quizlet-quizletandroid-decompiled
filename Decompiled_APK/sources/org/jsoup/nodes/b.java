package org.jsoup.nodes;

import com.google.android.gms.internal.ads.C2778wC;
import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import org.jsoup.SerializationException;
import org.jsoup.helper.ValidationException;

/* loaded from: classes3.dex */
public final class b implements Iterable, Cloneable {
    public int a = 0;
    public String[] b = new String[3];
    public Object[] c = new Object[3];

    public static boolean r(String str) {
        return str != null && str.length() > 1 && str.charAt(0) == '/';
    }

    public final void b(b bVar) {
        int i = bVar.a;
        if (i == 0) {
            return;
        }
        e(this.a + i);
        int i2 = 0;
        boolean z = this.a != 0;
        while (true) {
            if (i2 < bVar.a && r(bVar.b[i2])) {
                i2++;
            } else {
                if (i2 >= bVar.a) {
                    return;
                }
                a aVar = new a(bVar.b[i2], (String) bVar.c[i2], bVar);
                i2++;
                if (z) {
                    t(aVar);
                } else {
                    String str = aVar.a;
                    String str2 = aVar.b;
                    if (str2 == null) {
                        str2 = "";
                    }
                    c(str, str2);
                }
            }
        }
    }

    public final void c(String str, String str2) {
        e(this.a + 1);
        String[] strArr = this.b;
        int i = this.a;
        strArr[i] = str;
        this.c[i] = str2;
        this.a = i + 1;
    }

    public final void e(int i) {
        org.jsoup.helper.b.d(i >= this.a);
        String[] strArr = this.b;
        int length = strArr.length;
        if (length >= i) {
            return;
        }
        int i2 = length >= 3 ? this.a * 2 : 3;
        if (i <= i2) {
            i = i2;
        }
        this.b = (String[]) Arrays.copyOf(strArr, i);
        this.c = Arrays.copyOf(this.c, i);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || b.class != obj.getClass()) {
            return false;
        }
        b bVar = (b) obj;
        if (this.a != bVar.a) {
            return false;
        }
        for (int i = 0; i < this.a; i++) {
            int iN = bVar.n(this.b[i]);
            if (iN == -1) {
                return false;
            }
            Object obj2 = this.c[i];
            Object obj3 = bVar.c[iN];
            if (obj2 == null) {
                if (obj3 != null) {
                    return false;
                }
            } else if (!obj2.equals(obj3)) {
                return false;
            }
        }
        return true;
    }

    /* renamed from: g, reason: merged with bridge method [inline-methods] */
    public final b clone() {
        try {
            b bVar = (b) super.clone();
            bVar.a = this.a;
            bVar.b = (String[]) Arrays.copyOf(this.b, this.a);
            bVar.c = Arrays.copyOf(this.c, this.a);
            return bVar;
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0039  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int h(org.jsoup.parser.D r8) {
        /*
            r7 = this;
            int r0 = r7.a
            r1 = 0
            r2 = 1
            if (r0 != 0) goto L8
            r0 = r2
            goto L9
        L8:
            r0 = r1
        L9:
            if (r0 == 0) goto Lc
            return r1
        Lc:
            boolean r8 = r8.b
            r0 = r1
        Lf:
            java.lang.String[] r3 = r7.b
            int r3 = r3.length
            if (r1 >= r3) goto L44
            int r3 = r1 + 1
            r4 = r3
        L17:
            java.lang.String[] r5 = r7.b
            int r6 = r5.length
            if (r4 >= r6) goto L42
            r6 = r5[r4]
            if (r6 != 0) goto L21
            goto L42
        L21:
            if (r8 == 0) goto L2b
            r5 = r5[r1]
            boolean r5 = r5.equals(r6)
            if (r5 != 0) goto L39
        L2b:
            if (r8 != 0) goto L40
            java.lang.String[] r5 = r7.b
            r6 = r5[r1]
            r5 = r5[r4]
            boolean r5 = r6.equalsIgnoreCase(r5)
            if (r5 == 0) goto L40
        L39:
            int r0 = r0 + 1
            r7.u(r4)
            int r4 = r4 + (-1)
        L40:
            int r4 = r4 + r2
            goto L17
        L42:
            r1 = r3
            goto Lf
        L44:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.jsoup.nodes.b.h(org.jsoup.parser.D):int");
    }

    public final int hashCode() {
        return Arrays.hashCode(this.c) + (((this.a * 31) + Arrays.hashCode(this.b)) * 31);
    }

    public final String i(String str) {
        Object obj;
        int iN = n(str);
        return (iN == -1 || (obj = this.c[iN]) == null) ? "" : (String) obj;
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return new C2778wC(this, 1);
    }

    public final String k(String str) {
        Object obj;
        int iO = o(str);
        return (iO == -1 || (obj = this.c[iO]) == null) ? "" : (String) obj;
    }

    public final void m(StringBuilder sb, f fVar) {
        int i = this.a;
        for (int i2 = 0; i2 < i; i2++) {
            if (!r(this.b[i2])) {
                String strB = a.b(fVar.h, this.b[i2]);
                if (strB != null) {
                    a.c(strB, (String) this.c[i2], sb.append(' '), fVar);
                }
            }
        }
    }

    public final int n(String str) {
        org.jsoup.helper.b.g(str);
        for (int i = 0; i < this.a; i++) {
            if (str.equals(this.b[i])) {
                return i;
            }
        }
        return -1;
    }

    public final int o(String str) {
        org.jsoup.helper.b.g(str);
        for (int i = 0; i < this.a; i++) {
            if (str.equalsIgnoreCase(this.b[i])) {
                return i;
            }
        }
        return -1;
    }

    public final void s(String str, String str2) {
        org.jsoup.helper.b.g(str);
        int iN = n(str);
        if (iN != -1) {
            this.c[iN] = str2;
        } else {
            c(str, str2);
        }
    }

    public final void t(a aVar) {
        String str = aVar.b;
        if (str == null) {
            str = "";
        }
        s(aVar.a, str);
        aVar.c = this;
    }

    public final String toString() {
        StringBuilder sbB = org.jsoup.internal.a.b();
        try {
            m(sbB, new g("").j);
            return org.jsoup.internal.a.g(sbB);
        } catch (IOException e) {
            throw new SerializationException(e);
        }
    }

    public final void u(int i) {
        int i2 = this.a;
        if (i >= i2) {
            throw new ValidationException("Must be false");
        }
        int i3 = (i2 - i) - 1;
        if (i3 > 0) {
            String[] strArr = this.b;
            int i4 = i + 1;
            System.arraycopy(strArr, i4, strArr, i, i3);
            Object[] objArr = this.c;
            System.arraycopy(objArr, i4, objArr, i, i3);
        }
        int i5 = this.a - 1;
        this.a = i5;
        this.b[i5] = null;
        this.c[i5] = null;
    }
}
