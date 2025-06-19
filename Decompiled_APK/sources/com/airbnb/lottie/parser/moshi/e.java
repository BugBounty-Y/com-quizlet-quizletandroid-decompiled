package com.airbnb.lottie.parser.moshi;

import java.io.EOFException;
import java.io.IOException;
import kotlin.text.Charsets;
import okio.A;
import okio.C5091h;
import okio.k;

/* loaded from: classes.dex */
public final class e extends d {
    public static final k l;
    public static final k m;
    public static final k n;
    public final A f;
    public final C5091h g;
    public int h;
    public long i;
    public int j;
    public String k;

    static {
        k kVar = k.d;
        l = com.quizlet.quizletandroid.ui.common.images.capture.b.i("'\\");
        m = com.quizlet.quizletandroid.ui.common.images.capture.b.i("\"\\");
        n = com.quizlet.quizletandroid.ui.common.images.capture.b.i("{}[]:, \n\t\r\f/\\;#=");
        com.quizlet.quizletandroid.ui.common.images.capture.b.i("\n\r");
        com.quizlet.quizletandroid.ui.common.images.capture.b.i("*/");
    }

    public e(A a) {
        this.b = new int[32];
        this.c = new String[32];
        this.d = new int[32];
        this.h = 0;
        this.f = a;
        this.g = a.b;
        C(6);
    }

    @Override // com.airbnb.lottie.parser.moshi.d
    public final int B() throws EOFException, b {
        int iC0 = this.h;
        if (iC0 == 0) {
            iC0 = c0();
        }
        switch (iC0) {
            case 1:
                return 3;
            case 2:
                return 4;
            case 3:
                return 1;
            case 4:
                return 2;
            case 5:
            case 6:
                return 8;
            case 7:
                return 9;
            case 8:
            case 9:
            case 10:
            case 11:
                return 6;
            case 12:
            case 13:
            case 14:
            case 15:
                return 5;
            case 16:
            case 17:
                return 7;
            case 18:
                return 10;
            default:
                throw new AssertionError();
        }
    }

    @Override // com.airbnb.lottie.parser.moshi.d
    public final int D(c cVar) {
        int iC0 = this.h;
        if (iC0 == 0) {
            iC0 = c0();
        }
        if (iC0 < 12 || iC0 > 15) {
            return -1;
        }
        if (iC0 == 15) {
            return d0(this.k, cVar);
        }
        int iJ0 = this.f.j0(cVar.b);
        if (iJ0 != -1) {
            this.h = 0;
            this.c[this.a - 1] = cVar.a[iJ0];
            return iJ0;
        }
        String str = this.c[this.a - 1];
        String strL0 = l0();
        int iD0 = d0(strL0, cVar);
        if (iD0 == -1) {
            this.h = 15;
            this.k = strL0;
            this.c[this.a - 1] = str;
        }
        return iD0;
    }

    @Override // com.airbnb.lottie.parser.moshi.d
    public final void P() {
        int iC0 = this.h;
        if (iC0 == 0) {
            iC0 = c0();
        }
        if (iC0 == 14) {
            long jX = this.f.x(n);
            C5091h c5091h = this.g;
            if (jX == -1) {
                jX = c5091h.b;
            }
            c5091h.skip(jX);
        } else if (iC0 == 13) {
            q0(m);
        } else if (iC0 == 12) {
            q0(l);
        } else if (iC0 != 15) {
            throw new a("Expected a name but was " + assistantMode.refactored.a.r(B()) + " at path " + j(), 0);
        }
        this.h = 0;
        this.c[this.a - 1] = "null";
    }

    @Override // com.airbnb.lottie.parser.moshi.d
    public final void Q() {
        int i = 0;
        do {
            int iC0 = this.h;
            if (iC0 == 0) {
                iC0 = c0();
            }
            if (iC0 == 3) {
                C(1);
            } else if (iC0 == 1) {
                C(3);
            } else {
                if (iC0 == 4) {
                    i--;
                    if (i < 0) {
                        throw new a("Expected a value but was " + assistantMode.refactored.a.r(B()) + " at path " + j(), 0);
                    }
                    this.a--;
                } else if (iC0 == 2) {
                    i--;
                    if (i < 0) {
                        throw new a("Expected a value but was " + assistantMode.refactored.a.r(B()) + " at path " + j(), 0);
                    }
                    this.a--;
                } else {
                    C5091h c5091h = this.g;
                    if (iC0 == 14 || iC0 == 10) {
                        long jX = this.f.x(n);
                        if (jX == -1) {
                            jX = c5091h.b;
                        }
                        c5091h.skip(jX);
                    } else if (iC0 == 9 || iC0 == 13) {
                        q0(m);
                    } else if (iC0 == 8 || iC0 == 12) {
                        q0(l);
                    } else if (iC0 == 17) {
                        c5091h.skip(this.j);
                    } else if (iC0 == 18) {
                        throw new a("Expected a value but was " + assistantMode.refactored.a.r(B()) + " at path " + j(), 0);
                    }
                }
                this.h = 0;
            }
            i++;
            this.h = 0;
        } while (i != 0);
        int[] iArr = this.d;
        int i2 = this.a - 1;
        iArr[i2] = iArr[i2] + 1;
        this.c[i2] = "null";
    }

    @Override // com.airbnb.lottie.parser.moshi.d
    public final void a() {
        int iC0 = this.h;
        if (iC0 == 0) {
            iC0 = c0();
        }
        if (iC0 == 3) {
            C(1);
            this.d[this.a - 1] = 0;
            this.h = 0;
        } else {
            throw new a("Expected BEGIN_ARRAY but was " + assistantMode.refactored.a.r(B()) + " at path " + j(), 0);
        }
    }

    public final void a0() throws b {
        Y("Use JsonReader.setLenient(true) to accept malformed JSON");
        throw null;
    }

    /* JADX WARN: Code restructure failed: missing block: B:135:0x0195, code lost:
    
        if (k0(r10) != false) goto L113;
     */
    /* JADX WARN: Code restructure failed: missing block: B:136:0x0197, code lost:
    
        if (r1 != 2) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:137:0x0199, code lost:
    
        if (r4 == false) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:139:0x019f, code lost:
    
        if (r12 != Long.MIN_VALUE) goto L141;
     */
    /* JADX WARN: Code restructure failed: missing block: B:140:0x01a1, code lost:
    
        if (r9 == false) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:142:0x01a5, code lost:
    
        if (r12 != r17) goto L144;
     */
    /* JADX WARN: Code restructure failed: missing block: B:143:0x01a7, code lost:
    
        if (r9 != false) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:144:0x01a9, code lost:
    
        if (r9 == false) goto L146;
     */
    /* JADX WARN: Code restructure failed: missing block: B:146:0x01ac, code lost:
    
        r12 = -r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:147:0x01ad, code lost:
    
        r22.i = r12;
        r7.skip(r2);
        r9 = 16;
        r22.h = 16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:148:0x01b8, code lost:
    
        if (r1 == 2) goto L153;
     */
    /* JADX WARN: Code restructure failed: missing block: B:150:0x01bb, code lost:
    
        if (r1 == 4) goto L153;
     */
    /* JADX WARN: Code restructure failed: missing block: B:152:0x01be, code lost:
    
        if (r1 != 7) goto L113;
     */
    /* JADX WARN: Code restructure failed: missing block: B:153:0x01c0, code lost:
    
        r22.j = r2;
        r9 = 17;
        r22.h = 17;
     */
    /* JADX WARN: Removed duplicated region for block: B:172:0x01ed A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:173:0x01ee  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0115 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0116  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int c0() throws java.io.EOFException, com.airbnb.lottie.parser.moshi.b {
        /*
            Method dump skipped, instructions count: 652
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.parser.moshi.e.c0():int");
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        this.h = 0;
        this.b[0] = 8;
        this.a = 1;
        this.g.d();
        this.f.close();
    }

    @Override // com.airbnb.lottie.parser.moshi.d
    public final void d() {
        int iC0 = this.h;
        if (iC0 == 0) {
            iC0 = c0();
        }
        if (iC0 == 1) {
            C(3);
            this.h = 0;
        } else {
            throw new a("Expected BEGIN_OBJECT but was " + assistantMode.refactored.a.r(B()) + " at path " + j(), 0);
        }
    }

    public final int d0(String str, c cVar) {
        int length = cVar.a.length;
        for (int i = 0; i < length; i++) {
            if (str.equals(cVar.a[i])) {
                this.h = 0;
                this.c[this.a - 1] = str;
                return i;
            }
        }
        return -1;
    }

    @Override // com.airbnb.lottie.parser.moshi.d
    public final void f() {
        int iC0 = this.h;
        if (iC0 == 0) {
            iC0 = c0();
        }
        if (iC0 != 4) {
            throw new a("Expected END_ARRAY but was " + assistantMode.refactored.a.r(B()) + " at path " + j(), 0);
        }
        int i = this.a;
        this.a = i - 1;
        int[] iArr = this.d;
        int i2 = i - 2;
        iArr[i2] = iArr[i2] + 1;
        this.h = 0;
    }

    @Override // com.airbnb.lottie.parser.moshi.d
    public final void i() {
        int iC0 = this.h;
        if (iC0 == 0) {
            iC0 = c0();
        }
        if (iC0 != 2) {
            throw new a("Expected END_OBJECT but was " + assistantMode.refactored.a.r(B()) + " at path " + j(), 0);
        }
        int i = this.a;
        int i2 = i - 1;
        this.a = i2;
        this.c[i2] = null;
        int[] iArr = this.d;
        int i3 = i - 2;
        iArr[i3] = iArr[i3] + 1;
        this.h = 0;
    }

    public final boolean k0(int i) throws b {
        if (i == 9 || i == 10 || i == 12 || i == 13 || i == 32) {
            return false;
        }
        if (i != 35) {
            if (i == 44) {
                return false;
            }
            if (i != 47 && i != 61) {
                if (i == 123 || i == 125 || i == 58) {
                    return false;
                }
                if (i != 59) {
                    switch (i) {
                        case 91:
                        case 93:
                            return false;
                        case 92:
                            break;
                        default:
                            return true;
                    }
                }
            }
        }
        a0();
        throw null;
    }

    @Override // com.airbnb.lottie.parser.moshi.d
    public final boolean l() throws EOFException, b {
        int iC0 = this.h;
        if (iC0 == 0) {
            iC0 = c0();
        }
        return (iC0 == 2 || iC0 == 4 || iC0 == 18) ? false : true;
    }

    public final String l0() {
        String strN0;
        int iC0 = this.h;
        if (iC0 == 0) {
            iC0 = c0();
        }
        if (iC0 == 14) {
            strN0 = o0();
        } else if (iC0 == 13) {
            strN0 = n0(m);
        } else if (iC0 == 12) {
            strN0 = n0(l);
        } else {
            if (iC0 != 15) {
                throw new a("Expected a name but was " + assistantMode.refactored.a.r(B()) + " at path " + j(), 0);
            }
            strN0 = this.k;
        }
        this.h = 0;
        this.c[this.a - 1] = strN0;
        return strN0;
    }

    public final int m0(boolean z) throws EOFException, b {
        int i = 0;
        while (true) {
            int i2 = i + 1;
            A a = this.f;
            if (!a.e(i2)) {
                if (z) {
                    throw new EOFException("End of input");
                }
                return -1;
            }
            long j = i;
            C5091h c5091h = this.g;
            byte bP = c5091h.p(j);
            if (bP != 10 && bP != 32 && bP != 13 && bP != 9) {
                c5091h.skip(j);
                if (bP == 47) {
                    if (a.e(2L)) {
                        a0();
                        throw null;
                    }
                } else if (bP == 35) {
                    a0();
                    throw null;
                }
                return bP;
            }
            i = i2;
        }
    }

    public final String n0(k kVar) throws EOFException, b {
        StringBuilder sb = null;
        while (true) {
            long jX = this.f.x(kVar);
            if (jX == -1) {
                Y("Unterminated string");
                throw null;
            }
            C5091h c5091h = this.g;
            if (c5091h.p(jX) != 92) {
                if (sb == null) {
                    String strC0 = c5091h.c0(jX, Charsets.UTF_8);
                    c5091h.readByte();
                    return strC0;
                }
                sb.append(c5091h.c0(jX, Charsets.UTF_8));
                c5091h.readByte();
                return sb.toString();
            }
            if (sb == null) {
                sb = new StringBuilder();
            }
            sb.append(c5091h.c0(jX, Charsets.UTF_8));
            c5091h.readByte();
            sb.append(p0());
        }
    }

    public final String o0() {
        long jX = this.f.x(n);
        C5091h c5091h = this.g;
        if (jX == -1) {
            return c5091h.U();
        }
        c5091h.getClass();
        return c5091h.c0(jX, Charsets.UTF_8);
    }

    @Override // com.airbnb.lottie.parser.moshi.d
    public final boolean p() {
        int iC0 = this.h;
        if (iC0 == 0) {
            iC0 = c0();
        }
        if (iC0 == 5) {
            this.h = 0;
            int[] iArr = this.d;
            int i = this.a - 1;
            iArr[i] = iArr[i] + 1;
            return true;
        }
        if (iC0 == 6) {
            this.h = 0;
            int[] iArr2 = this.d;
            int i2 = this.a - 1;
            iArr2[i2] = iArr2[i2] + 1;
            return false;
        }
        throw new a("Expected a boolean but was " + assistantMode.refactored.a.r(B()) + " at path " + j(), 0);
    }

    public final char p0() throws b, EOFException {
        int i;
        A a = this.f;
        if (!a.e(1L)) {
            Y("Unterminated escape sequence");
            throw null;
        }
        C5091h c5091h = this.g;
        byte b = c5091h.readByte();
        if (b == 10 || b == 34 || b == 39 || b == 47 || b == 92) {
            return (char) b;
        }
        if (b == 98) {
            return '\b';
        }
        if (b == 102) {
            return '\f';
        }
        if (b == 110) {
            return '\n';
        }
        if (b == 114) {
            return '\r';
        }
        if (b == 116) {
            return '\t';
        }
        if (b != 117) {
            Y("Invalid escape sequence: \\" + ((char) b));
            throw null;
        }
        if (!a.e(4L)) {
            throw new EOFException("Unterminated escape sequence at path " + j());
        }
        char c = 0;
        for (int i2 = 0; i2 < 4; i2++) {
            byte bP = c5091h.p(i2);
            char c2 = (char) (c << 4);
            if (bP >= 48 && bP <= 57) {
                i = bP - 48;
            } else if (bP >= 97 && bP <= 102) {
                i = bP - 87;
            } else {
                if (bP < 65 || bP > 70) {
                    Y("\\u".concat(c5091h.c0(4L, Charsets.UTF_8)));
                    throw null;
                }
                i = bP - 55;
            }
            c = (char) (i + c2);
        }
        c5091h.skip(4L);
        return c;
    }

    @Override // com.airbnb.lottie.parser.moshi.d
    public final double q() throws NumberFormatException, EOFException, b {
        int iC0 = this.h;
        if (iC0 == 0) {
            iC0 = c0();
        }
        if (iC0 == 16) {
            this.h = 0;
            int[] iArr = this.d;
            int i = this.a - 1;
            iArr[i] = iArr[i] + 1;
            return this.i;
        }
        if (iC0 == 17) {
            long j = this.j;
            C5091h c5091h = this.g;
            c5091h.getClass();
            this.k = c5091h.c0(j, Charsets.UTF_8);
        } else if (iC0 == 9) {
            this.k = n0(m);
        } else if (iC0 == 8) {
            this.k = n0(l);
        } else if (iC0 == 10) {
            this.k = o0();
        } else if (iC0 != 11) {
            throw new a("Expected a double but was " + assistantMode.refactored.a.r(B()) + " at path " + j(), 0);
        }
        this.h = 11;
        try {
            double d = Double.parseDouble(this.k);
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new b("JSON forbids NaN and infinities: " + d + " at path " + j());
            }
            this.k = null;
            this.h = 0;
            int[] iArr2 = this.d;
            int i2 = this.a - 1;
            iArr2[i2] = iArr2[i2] + 1;
            return d;
        } catch (NumberFormatException unused) {
            throw new a("Expected a double but was " + this.k + " at path " + j(), 0);
        }
    }

    public final void q0(k kVar) throws EOFException, b {
        while (true) {
            long jX = this.f.x(kVar);
            if (jX == -1) {
                Y("Unterminated string");
                throw null;
            }
            C5091h c5091h = this.g;
            if (c5091h.p(jX) != 92) {
                c5091h.skip(jX + 1);
                return;
            } else {
                c5091h.skip(jX + 1);
                p0();
            }
        }
    }

    @Override // com.airbnb.lottie.parser.moshi.d
    public final int r() {
        int iC0 = this.h;
        if (iC0 == 0) {
            iC0 = c0();
        }
        if (iC0 == 16) {
            long j = this.i;
            int i = (int) j;
            if (j == i) {
                this.h = 0;
                int[] iArr = this.d;
                int i2 = this.a - 1;
                iArr[i2] = iArr[i2] + 1;
                return i;
            }
            throw new a("Expected an int but was " + this.i + " at path " + j(), 0);
        }
        if (iC0 == 17) {
            long j2 = this.j;
            C5091h c5091h = this.g;
            c5091h.getClass();
            this.k = c5091h.c0(j2, Charsets.UTF_8);
        } else if (iC0 == 9 || iC0 == 8) {
            String strN0 = iC0 == 9 ? n0(m) : n0(l);
            this.k = strN0;
            try {
                int i3 = Integer.parseInt(strN0);
                this.h = 0;
                int[] iArr2 = this.d;
                int i4 = this.a - 1;
                iArr2[i4] = iArr2[i4] + 1;
                return i3;
            } catch (NumberFormatException unused) {
            }
        } else if (iC0 != 11) {
            throw new a("Expected an int but was " + assistantMode.refactored.a.r(B()) + " at path " + j(), 0);
        }
        this.h = 11;
        try {
            double d = Double.parseDouble(this.k);
            int i5 = (int) d;
            if (i5 != d) {
                throw new a("Expected an int but was " + this.k + " at path " + j(), 0);
            }
            this.k = null;
            this.h = 0;
            int[] iArr3 = this.d;
            int i6 = this.a - 1;
            iArr3[i6] = iArr3[i6] + 1;
            return i5;
        } catch (NumberFormatException unused2) {
            throw new a("Expected an int but was " + this.k + " at path " + j(), 0);
        }
    }

    public final String toString() {
        return "JsonReader(" + this.f + ")";
    }

    @Override // com.airbnb.lottie.parser.moshi.d
    public final String y() {
        String strC0;
        int iC0 = this.h;
        if (iC0 == 0) {
            iC0 = c0();
        }
        if (iC0 == 10) {
            strC0 = o0();
        } else if (iC0 == 9) {
            strC0 = n0(m);
        } else if (iC0 == 8) {
            strC0 = n0(l);
        } else if (iC0 == 11) {
            strC0 = this.k;
            this.k = null;
        } else if (iC0 == 16) {
            strC0 = Long.toString(this.i);
        } else {
            if (iC0 != 17) {
                throw new a("Expected a string but was " + assistantMode.refactored.a.r(B()) + " at path " + j(), 0);
            }
            long j = this.j;
            C5091h c5091h = this.g;
            c5091h.getClass();
            strC0 = c5091h.c0(j, Charsets.UTF_8);
        }
        this.h = 0;
        int[] iArr = this.d;
        int i = this.a - 1;
        iArr[i] = iArr[i] + 1;
        return strC0;
    }
}
