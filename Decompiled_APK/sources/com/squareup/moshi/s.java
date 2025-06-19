package com.squareup.moshi;

import java.io.IOException;
import java.util.Arrays;
import okio.InterfaceC5092i;

/* loaded from: classes3.dex */
public final class s extends w {
    public static final String[] j = new String[128];
    public final InterfaceC5092i h;
    public String i;

    static {
        for (int i = 0; i <= 31; i++) {
            j[i] = String.format("\\u%04x", Integer.valueOf(i));
        }
        String[] strArr = j;
        strArr[34] = "\\\"";
        strArr[92] = "\\\\";
        strArr[9] = "\\t";
        strArr[8] = "\\b";
        strArr[10] = "\\n";
        strArr[13] = "\\r";
        strArr[12] = "\\f";
    }

    public s(InterfaceC5092i interfaceC5092i) {
        int[] iArr = new int[32];
        this.b = iArr;
        this.c = new String[32];
        this.d = new int[32];
        this.g = -1;
        this.h = interfaceC5092i;
        this.a = 1;
        iArr[0] = 6;
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x002b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void a0(okio.InterfaceC5092i r7, java.lang.String r8) {
        /*
            java.lang.String[] r0 = com.squareup.moshi.s.j
            r1 = 34
            r7.v(r1)
            int r2 = r8.length()
            r3 = 0
            r4 = r3
        Ld:
            if (r3 >= r2) goto L36
            char r5 = r8.charAt(r3)
            r6 = 128(0x80, float:1.8E-43)
            if (r5 >= r6) goto L1c
            r5 = r0[r5]
            if (r5 != 0) goto L29
            goto L33
        L1c:
            r6 = 8232(0x2028, float:1.1535E-41)
            if (r5 != r6) goto L23
            java.lang.String r5 = "\\u2028"
            goto L29
        L23:
            r6 = 8233(0x2029, float:1.1537E-41)
            if (r5 != r6) goto L33
            java.lang.String r5 = "\\u2029"
        L29:
            if (r4 >= r3) goto L2e
            r7.O(r4, r3, r8)
        L2e:
            r7.H(r5)
            int r4 = r3 + 1
        L33:
            int r3 = r3 + 1
            goto Ld
        L36:
            if (r4 >= r2) goto L3b
            r7.O(r4, r2, r8)
        L3b:
            r7.v(r1)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.squareup.moshi.s.a0(okio.i, java.lang.String):void");
    }

    @Override // com.squareup.moshi.w
    public final s B(Number number) {
        if (number == null) {
            p();
            return this;
        }
        String string = number.toString();
        if (string.equals("-Infinity") || string.equals("Infinity") || string.equals("NaN")) {
            throw new IllegalArgumentException("Numeric values must be finite, but was " + number);
        }
        if (this.f) {
            this.f = false;
            l(string);
            return this;
        }
        c0();
        P();
        this.h.H(string);
        int[] iArr = this.d;
        int i = this.a - 1;
        iArr[i] = iArr[i] + 1;
        return this;
    }

    @Override // com.squareup.moshi.w
    public final s C(String str) {
        if (str == null) {
            p();
            return this;
        }
        if (this.f) {
            this.f = false;
            l(str);
            return this;
        }
        c0();
        P();
        a0(this.h, str);
        int[] iArr = this.d;
        int i = this.a - 1;
        iArr[i] = iArr[i] + 1;
        return this;
    }

    @Override // com.squareup.moshi.w
    public final s D(boolean z) {
        if (this.f) {
            throw new IllegalStateException("Boolean cannot be used as a map key in JSON at path " + i());
        }
        c0();
        P();
        this.h.H(z ? "true" : "false");
        int[] iArr = this.d;
        int i = this.a - 1;
        iArr[i] = iArr[i] + 1;
        return this;
    }

    public final void P() {
        int iQ = q();
        int i = 2;
        if (iQ != 1) {
            InterfaceC5092i interfaceC5092i = this.h;
            if (iQ == 2) {
                interfaceC5092i.v(44);
            } else if (iQ == 4) {
                interfaceC5092i.H(":");
                i = 5;
            } else {
                if (iQ == 9) {
                    throw new IllegalStateException("Sink from valueSink() was not closed");
                }
                if (iQ != 6) {
                    if (iQ != 7) {
                        throw new IllegalStateException("Nesting problem.");
                    }
                    throw new IllegalStateException("JSON must have only one top-level value.");
                }
                i = 7;
            }
        }
        this.b[this.a - 1] = i;
    }

    public final void Q(int i, char c, int i2) {
        int iQ = q();
        if (iQ != i2 && iQ != i) {
            throw new IllegalStateException("Nesting problem.");
        }
        if (this.i != null) {
            throw new IllegalStateException("Dangling name: " + this.i);
        }
        int i3 = this.a;
        int i4 = ~this.g;
        if (i3 == i4) {
            this.g = i4;
            return;
        }
        int i5 = i3 - 1;
        this.a = i5;
        this.c[i5] = null;
        int[] iArr = this.d;
        int i6 = i3 - 2;
        iArr[i6] = iArr[i6] + 1;
        this.h.v(c);
    }

    public final void Y(int i, char c, int i2) {
        int i3;
        int i4 = this.a;
        int i5 = this.g;
        if (i4 == i5 && ((i3 = this.b[i4 - 1]) == i || i3 == i2)) {
            this.g = ~i5;
            return;
        }
        P();
        int i6 = this.a;
        int[] iArr = this.b;
        if (i6 == iArr.length) {
            if (i6 == 256) {
                throw new JsonDataException("Nesting too deep at " + i() + ": circular reference?");
            }
            this.b = Arrays.copyOf(iArr, iArr.length * 2);
            String[] strArr = this.c;
            this.c = (String[]) Arrays.copyOf(strArr, strArr.length * 2);
            int[] iArr2 = this.d;
            this.d = Arrays.copyOf(iArr2, iArr2.length * 2);
        }
        int[] iArr3 = this.b;
        int i7 = this.a;
        this.a = i7 + 1;
        iArr3[i7] = i;
        this.d[i7] = 0;
        this.h.v(c);
    }

    @Override // com.squareup.moshi.w
    public final s a() {
        if (this.f) {
            throw new IllegalStateException("Array cannot be used as a map key in JSON at path " + i());
        }
        c0();
        Y(1, '[', 2);
        return this;
    }

    public final void c0() {
        if (this.i != null) {
            int iQ = q();
            InterfaceC5092i interfaceC5092i = this.h;
            if (iQ == 5) {
                interfaceC5092i.v(44);
            } else if (iQ != 3) {
                throw new IllegalStateException("Nesting problem.");
            }
            this.b[this.a - 1] = 4;
            a0(interfaceC5092i, this.i);
            this.i = null;
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        this.h.close();
        int i = this.a;
        if (i > 1 || (i == 1 && this.b[i - 1] != 7)) {
            throw new IOException("Incomplete document");
        }
        this.a = 0;
    }

    @Override // com.squareup.moshi.w
    public final s d() {
        if (this.f) {
            throw new IllegalStateException("Object cannot be used as a map key in JSON at path " + i());
        }
        c0();
        Y(3, '{', 5);
        return this;
    }

    @Override // com.squareup.moshi.w
    public final s f() {
        this.f = false;
        Q(3, '}', 5);
        return this;
    }

    @Override // java.io.Flushable
    public final void flush() {
        if (this.a == 0) {
            throw new IllegalStateException("JsonWriter is closed.");
        }
        this.h.flush();
    }

    @Override // com.squareup.moshi.w
    public final s l(String str) {
        if (str == null) {
            throw new NullPointerException("name == null");
        }
        if (this.a == 0) {
            throw new IllegalStateException("JsonWriter is closed.");
        }
        int iQ = q();
        if ((iQ != 3 && iQ != 5) || this.i != null || this.f) {
            throw new IllegalStateException("Nesting problem.");
        }
        this.i = str;
        this.c[this.a - 1] = str;
        return this;
    }

    @Override // com.squareup.moshi.w
    public final s p() {
        if (this.f) {
            throw new IllegalStateException("null cannot be used as a map key in JSON at path " + i());
        }
        if (this.i != null) {
            if (!this.e) {
                this.i = null;
                return this;
            }
            c0();
        }
        P();
        this.h.H("null");
        int[] iArr = this.d;
        int i = this.a - 1;
        iArr[i] = iArr[i] + 1;
        return this;
    }

    @Override // com.squareup.moshi.w
    public final s r(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) {
            throw new IllegalArgumentException("Numeric values must be finite, but was " + d);
        }
        if (this.f) {
            this.f = false;
            l(Double.toString(d));
            return this;
        }
        c0();
        P();
        this.h.H(Double.toString(d));
        int[] iArr = this.d;
        int i = this.a - 1;
        iArr[i] = iArr[i] + 1;
        return this;
    }

    @Override // com.squareup.moshi.w
    public final s y(long j2) {
        if (this.f) {
            this.f = false;
            l(Long.toString(j2));
            return this;
        }
        c0();
        P();
        this.h.H(Long.toString(j2));
        int[] iArr = this.d;
        int i = this.a - 1;
        iArr[i] = iArr[i] + 1;
        return this;
    }
}
