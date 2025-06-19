package org.jsoup.parser;

import com.google.android.gms.dynamite.descriptors.com.google.android.gms.measurement.dynamite.ModuleDescriptor;
import java.io.IOException;
import java.util.Arrays;
import org.jsoup.helper.ValidationException;

/* loaded from: classes3.dex */
public final class N {
    public static final char[] t;
    public static final int[] u = {8364, 129, 8218, 402, 8222, 8230, 8224, 8225, 710, 8240, 352, 8249, 338, ModuleDescriptor.MODULE_VERSION, 381, 143, 144, 8216, 8217, 8220, 8221, 8226, 8211, 8212, 732, 8482, 353, 8250, 339, 157, 382, 376};
    public final C5094a a;
    public final C b;
    public e1 c = e1.a;
    public androidx.sqlite.db.b d = null;
    public boolean e = false;
    public String f = null;
    public final StringBuilder g = new StringBuilder(1024);
    public final StringBuilder h = new StringBuilder(1024);
    public final L i;
    public final K j;
    public M k;
    public final G l;
    public final I m;
    public final H n;
    public String o;
    public String p;
    public int q;
    public final int[] r;
    public final int[] s;

    static {
        char[] cArr = {'\t', '\n', '\r', '\f', ' ', '<', '&'};
        t = cArr;
        Arrays.sort(cArr);
    }

    public N(C5094a c5094a, C c) {
        L l = new L();
        this.i = l;
        this.j = new K();
        this.k = l;
        this.l = new G();
        this.m = new I();
        this.n = new H();
        this.q = -1;
        this.r = new int[1];
        this.s = new int[2];
        this.a = c5094a;
        this.b = c;
    }

    public final void a(String str, Object... objArr) {
        C c = this.b;
        if (c.b()) {
            String str2 = String.format("Invalid character reference: ".concat(str), objArr);
            io.ktor.utils.io.A a = new io.ktor.utils.io.A();
            C5094a c5094a = this.a;
            c5094a.getClass();
            a.b = c5094a.m();
            a.c = str2;
            c.add(a);
        }
    }

    public final int[] b(Character ch, boolean z) throws IOException {
        int i;
        char c;
        char c2;
        char c3;
        char c4;
        char c5;
        int[] iArr;
        int i2;
        String strC;
        char c6;
        int iIntValue;
        int i3;
        char c7;
        C5094a c5094a = this.a;
        if (!c5094a.n() && (ch == null || ch.charValue() != c5094a.l())) {
            char[] cArr = t;
            c5094a.b();
            if (c5094a.n() || Arrays.binarySearch(cArr, c5094a.a[c5094a.e]) < 0) {
                if (c5094a.c - c5094a.e < 1024) {
                    c5094a.d = 0;
                }
                c5094a.b();
                c5094a.g = c5094a.e;
                boolean zP = c5094a.p("#");
                int[] iArr2 = this.r;
                if (zP) {
                    boolean zQ = c5094a.q("X");
                    if (zQ) {
                        c5094a.b();
                        int i4 = c5094a.e;
                        while (true) {
                            i3 = c5094a.e;
                            iArr = null;
                            if (i3 >= c5094a.c || (((c7 = c5094a.a[i3]) < '0' || c7 > '9') && ((c7 < 'A' || c7 > 'F') && (c7 < 'a' || c7 > 'f')))) {
                                break;
                            }
                            c5094a.e = i3 + 1;
                        }
                        strC = C5094a.c(c5094a.a, c5094a.h, i4, i3 - i4);
                    } else {
                        iArr = null;
                        c5094a.b();
                        int i5 = c5094a.e;
                        while (true) {
                            i2 = c5094a.e;
                            if (i2 >= c5094a.c || (c6 = c5094a.a[i2]) < '0' || c6 > '9') {
                                break;
                            }
                            c5094a.e = i2 + 1;
                        }
                        strC = C5094a.c(c5094a.a, c5094a.h, i5, i2 - i5);
                    }
                    if (strC.length() == 0) {
                        a("numeric reference with no numerals", new Object[0]);
                        c5094a.x();
                        return iArr;
                    }
                    c5094a.g = -1;
                    if (!c5094a.p(";")) {
                        a("missing semicolon on [&#%s]", strC);
                    }
                    try {
                        iIntValue = Integer.valueOf(strC, zQ ? 16 : 10).intValue();
                    } catch (NumberFormatException unused) {
                        iIntValue = -1;
                    }
                    if (iIntValue == -1 || ((iIntValue >= 55296 && iIntValue <= 57343) || iIntValue > 1114111)) {
                        a("character [%s] outside of valid range", Integer.valueOf(iIntValue));
                        iArr2[0] = 65533;
                    } else {
                        if (iIntValue >= 128 && iIntValue < 160) {
                            a("character [%s] is not a valid unicode code point", Integer.valueOf(iIntValue));
                            iIntValue = u[iIntValue - 128];
                        }
                        iArr2[0] = iIntValue;
                    }
                    return iArr2;
                }
                c5094a.b();
                int i6 = c5094a.e;
                while (true) {
                    int i7 = c5094a.e;
                    if (i7 >= c5094a.c || (((c5 = c5094a.a[i7]) < 'A' || c5 > 'Z') && ((c5 < 'a' || c5 > 'z') && !Character.isLetter(c5)))) {
                        break;
                    }
                    c5094a.e++;
                }
                while (true) {
                    i = c5094a.e;
                    if (i >= c5094a.c || (c4 = c5094a.a[i]) < '0' || c4 > '9') {
                        break;
                    }
                    c5094a.e = i + 1;
                }
                String strC2 = C5094a.c(c5094a.a, c5094a.h, i6, i - i6);
                boolean zR = c5094a.r(';');
                char[] cArr2 = org.jsoup.nodes.k.a;
                org.jsoup.nodes.j jVar = org.jsoup.nodes.j.base;
                int iBinarySearch = Arrays.binarySearch(jVar.a, strC2);
                if ((iBinarySearch >= 0 ? jVar.b[iBinarySearch] : -1) == -1) {
                    org.jsoup.nodes.j jVar2 = org.jsoup.nodes.j.extended;
                    int iBinarySearch2 = Arrays.binarySearch(jVar2.a, strC2);
                    if ((iBinarySearch2 >= 0 ? jVar2.b[iBinarySearch2] : -1) == -1 || !zR) {
                        c5094a.x();
                        if (!zR) {
                            return null;
                        }
                        a("invalid named reference [%s]", strC2);
                        return null;
                    }
                }
                if (z && (c5094a.u() || ((!c5094a.n() && (c3 = c5094a.a[c5094a.e]) >= '0' && c3 <= '9') || c5094a.s('=', '-', '_')))) {
                    c5094a.x();
                    return null;
                }
                c5094a.g = -1;
                if (!c5094a.p(";")) {
                    a("missing semicolon on [&%s]", strC2);
                }
                String str = (String) org.jsoup.nodes.k.b.get(strC2);
                int[] iArr3 = this.s;
                if (str != null) {
                    iArr3[0] = str.codePointAt(0);
                    iArr3[1] = str.codePointAt(1);
                    c2 = 1;
                    c = 2;
                } else {
                    org.jsoup.nodes.j jVar3 = org.jsoup.nodes.j.extended;
                    int iBinarySearch3 = Arrays.binarySearch(jVar3.a, strC2);
                    int i8 = iBinarySearch3 >= 0 ? jVar3.b[iBinarySearch3] : -1;
                    if (i8 != -1) {
                        iArr3[0] = i8;
                        c2 = 1;
                        c = 1;
                    } else {
                        c = 0;
                        c2 = 1;
                    }
                }
                if (c == c2) {
                    iArr2[0] = iArr3[0];
                    return iArr2;
                }
                if (c == 2) {
                    return iArr3;
                }
                throw new ValidationException("Unexpected characters returned for ".concat(strC2));
            }
        }
        return null;
    }

    public final M c(boolean z) {
        M m;
        if (z) {
            m = this.i;
            m.q();
        } else {
            m = this.j;
            m.q();
        }
        this.k = m;
        return m;
    }

    public final void d() {
        androidx.sqlite.db.b.r(this.h);
    }

    public final void e(char c) {
        if (this.f == null) {
            this.f = String.valueOf(c);
        } else {
            StringBuilder sb = this.g;
            if (sb.length() == 0) {
                sb.append(this.f);
            }
            sb.append(c);
        }
        this.l.getClass();
        this.a.getClass();
    }

    public final void f(androidx.sqlite.db.b bVar) {
        if (this.e) {
            throw new ValidationException("Must be false");
        }
        this.d = bVar;
        this.e = true;
        bVar.getClass();
        C5094a c5094a = this.a;
        c5094a.getClass();
        this.q = -1;
        int i = bVar.b;
        if (i == 2) {
            this.o = ((L) bVar).c;
            this.p = null;
        } else if (i == 3) {
            K k = (K) bVar;
            if (k.z()) {
                Object[] objArr = {k.d};
                C c = this.b;
                if (c.b()) {
                    c.add(new io.ktor.utils.io.A(c5094a, "Attributes incorrectly present on end tag [/%s]", objArr));
                }
            }
        }
    }

    public final void g(String str) {
        if (this.f == null) {
            this.f = str;
        } else {
            StringBuilder sb = this.g;
            if (sb.length() == 0) {
                sb.append(this.f);
            }
            sb.append(str);
        }
        this.l.getClass();
        this.a.getClass();
    }

    public final void h(StringBuilder sb) {
        if (this.f == null) {
            this.f = sb.toString();
        } else {
            StringBuilder sb2 = this.g;
            if (sb2.length() == 0) {
                sb2.append(this.f);
            }
            sb2.append((CharSequence) sb);
        }
        this.l.getClass();
        this.a.getClass();
    }

    public final void i() {
        f(this.n);
    }

    public final void j() {
        f(this.m);
    }

    public final void k() {
        M m = this.k;
        if (m.g) {
            m.C();
        }
        f(this.k);
    }

    public final void l(e1 e1Var) {
        C c = this.b;
        if (c.b()) {
            c.add(new io.ktor.utils.io.A(this.a, "Unexpectedly reached end of file (EOF) in input state [%s]", new Object[]{e1Var}));
        }
    }

    public final void m(e1 e1Var) {
        C c = this.b;
        if (c.b()) {
            C5094a c5094a = this.a;
            c.add(new io.ktor.utils.io.A(c5094a, "Unexpected character '%s' in input state [%s]", new Object[]{Character.valueOf(c5094a.l()), e1Var}));
        }
    }

    public final boolean n() {
        return this.o != null && this.k.A().equalsIgnoreCase(this.o);
    }

    public final void o(e1 e1Var) {
        int iOrdinal = e1Var.ordinal();
        C5094a c5094a = this.a;
        if (iOrdinal != 0) {
            if (iOrdinal == 7) {
                c5094a.w();
            }
        } else if (this.q == -1) {
            this.q = c5094a.w();
        }
        this.c = e1Var;
    }
}
