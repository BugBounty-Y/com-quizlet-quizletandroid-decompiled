package com.google.zxing.datamatrix.encoder;

import java.nio.charset.StandardCharsets;

/* loaded from: classes2.dex */
public final class c {
    public final String a;
    public f b;
    public final StringBuilder c;
    public int d;
    public int e;
    public e f;
    public int g;

    public c(String str) {
        byte[] bytes = str.getBytes(StandardCharsets.ISO_8859_1);
        StringBuilder sb = new StringBuilder(bytes.length);
        int length = bytes.length;
        for (int i = 0; i < length; i++) {
            char c = (char) (bytes[i] & 255);
            if (c == '?' && str.charAt(i) != '?') {
                throw new IllegalArgumentException("Message contains characters outside ISO-8859-1 encoding.");
            }
            sb.append(c);
        }
        this.a = sb.toString();
        this.b = f.a;
        this.c = new StringBuilder(str.length());
        this.e = -1;
    }

    public final char a() {
        return this.a.charAt(this.d);
    }

    public final boolean b() {
        return this.d < this.a.length() - this.g;
    }

    public final void c(int i) {
        e eVar = this.f;
        if (eVar == null || i > eVar.b) {
            this.f = e.e(i, this.b);
        }
    }

    public final void d(char c) {
        this.c.append(c);
    }
}
