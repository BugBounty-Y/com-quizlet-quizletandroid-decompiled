package com.google.gson.stream;

import java.io.Closeable;
import java.io.Flushable;
import java.io.IOException;
import java.io.Writer;
import java.util.Arrays;

/* loaded from: classes2.dex */
public class b implements Closeable, Flushable, AutoCloseable {
    public static final String[] h = new String[128];
    public final Writer a;
    public int[] b;
    public int c;
    public final String d;
    public boolean e;
    public String f;
    public final boolean g;

    static {
        for (int i = 0; i <= 31; i++) {
            h[i] = String.format("\\u%04x", Integer.valueOf(i));
        }
        String[] strArr = h;
        strArr[34] = "\\\"";
        strArr[92] = "\\\\";
        strArr[9] = "\\t";
        strArr[8] = "\\b";
        strArr[10] = "\\n";
        strArr[13] = "\\r";
        strArr[12] = "\\f";
        String[] strArr2 = (String[]) strArr.clone();
        strArr2[60] = "\\u003c";
        strArr2[62] = "\\u003e";
        strArr2[38] = "\\u0026";
        strArr2[61] = "\\u003d";
        strArr2[39] = "\\u0027";
    }

    public b(Writer writer) {
        int[] iArr = new int[32];
        this.b = iArr;
        this.c = 0;
        if (iArr.length == 0) {
            this.b = Arrays.copyOf(iArr, 0);
        }
        int[] iArr2 = this.b;
        int i = this.c;
        this.c = i + 1;
        iArr2[i] = 6;
        this.d = ":";
        this.g = true;
        if (writer == null) {
            throw new NullPointerException("out == null");
        }
        this.a = writer;
    }

    public final void a() throws IOException {
        int i = i();
        if (i == 1) {
            this.b[this.c - 1] = 2;
            return;
        }
        Writer writer = this.a;
        if (i == 2) {
            writer.append(',');
            return;
        }
        if (i == 4) {
            writer.append((CharSequence) this.d);
            this.b[this.c - 1] = 5;
            return;
        }
        if (i != 6) {
            if (i != 7) {
                throw new IllegalStateException("Nesting problem.");
            }
            if (!this.e) {
                throw new IllegalStateException("JSON must have only one top-level value.");
            }
        }
        this.b[this.c - 1] = 7;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        this.a.close();
        int i = this.c;
        if (i > 1 || (i == 1 && this.b[i - 1] != 7)) {
            throw new IOException("Incomplete document");
        }
        this.c = 0;
    }

    public final void d(int i, char c, int i2) throws IOException {
        int i3 = i();
        if (i3 != i2 && i3 != i) {
            throw new IllegalStateException("Nesting problem.");
        }
        if (this.f == null) {
            this.c--;
            this.a.write(c);
        } else {
            throw new IllegalStateException("Dangling name: " + this.f);
        }
    }

    public b f() throws IOException {
        if (this.f != null) {
            if (!this.g) {
                this.f = null;
                return this;
            }
            l();
        }
        a();
        this.a.write("null");
        return this;
    }

    @Override // java.io.Flushable
    public void flush() throws IOException {
        if (this.c == 0) {
            throw new IllegalStateException("JsonWriter is closed.");
        }
        this.a.flush();
    }

    public final int i() {
        int i = this.c;
        if (i != 0) {
            return this.b[i - 1];
        }
        throw new IllegalStateException("JsonWriter is closed.");
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x002d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void j(java.lang.String r9) throws java.io.IOException {
        /*
            r8 = this;
            java.lang.String[] r0 = com.google.gson.stream.b.h
            java.io.Writer r1 = r8.a
            r2 = 34
            r1.write(r2)
            int r3 = r9.length()
            r4 = 0
            r5 = r4
        Lf:
            if (r4 >= r3) goto L3a
            char r6 = r9.charAt(r4)
            r7 = 128(0x80, float:1.8E-43)
            if (r6 >= r7) goto L1e
            r6 = r0[r6]
            if (r6 != 0) goto L2b
            goto L37
        L1e:
            r7 = 8232(0x2028, float:1.1535E-41)
            if (r6 != r7) goto L25
            java.lang.String r6 = "\\u2028"
            goto L2b
        L25:
            r7 = 8233(0x2029, float:1.1537E-41)
            if (r6 != r7) goto L37
            java.lang.String r6 = "\\u2029"
        L2b:
            if (r5 >= r4) goto L32
            int r7 = r4 - r5
            r1.write(r9, r5, r7)
        L32:
            r1.write(r6)
            int r5 = r4 + 1
        L37:
            int r4 = r4 + 1
            goto Lf
        L3a:
            if (r5 >= r3) goto L40
            int r3 = r3 - r5
            r1.write(r9, r5, r3)
        L40:
            r1.write(r2)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.gson.stream.b.j(java.lang.String):void");
    }

    public final void l() throws IOException {
        if (this.f != null) {
            int i = i();
            if (i == 5) {
                this.a.write(44);
            } else if (i != 3) {
                throw new IllegalStateException("Nesting problem.");
            }
            this.b[this.c - 1] = 4;
            j(this.f);
            this.f = null;
        }
    }
}
