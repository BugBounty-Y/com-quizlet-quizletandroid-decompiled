package org.jsoup.nodes;

import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;

/* loaded from: classes3.dex */
public final class f implements Cloneable {
    public int d;
    public j a = j.base;
    public Charset b = org.jsoup.helper.a.a;
    public final ThreadLocal c = new ThreadLocal();
    public boolean e = true;
    public final int f = 1;
    public final int g = 30;
    public int h = 1;

    /* renamed from: b, reason: merged with bridge method [inline-methods] */
    public final f clone() {
        try {
            f fVar = (f) super.clone();
            String strName = this.b.name();
            fVar.getClass();
            fVar.b = Charset.forName(strName);
            fVar.a = j.valueOf(this.a.name());
            return fVar;
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    public final CharsetEncoder c() {
        CharsetEncoder charsetEncoderNewEncoder = this.b.newEncoder();
        this.c.set(charsetEncoderNewEncoder);
        String strName = charsetEncoderNewEncoder.charset().name();
        this.d = strName.equals("US-ASCII") ? 1 : strName.startsWith("UTF-") ? 2 : 3;
        return charsetEncoderNewEncoder;
    }
}
