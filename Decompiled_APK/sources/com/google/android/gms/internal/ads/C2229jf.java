package com.google.android.gms.internal.ads;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.jf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2229jf {
    public static final C2229jf e = new C2229jf(-1, -1, -1);
    public final int a;
    public final int b;
    public final int c;
    public final int d;

    public C2229jf(int i, int i2, int i3) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = Yo.c(i3) ? Yo.o(i3) * i2 : -1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C2229jf)) {
            return false;
        }
        C2229jf c2229jf = (C2229jf) obj;
        return this.a == c2229jf.a && this.b == c2229jf.b && this.c == c2229jf.c;
    }

    public final int hashCode() {
        return Objects.hash(Integer.valueOf(this.a), Integer.valueOf(this.b), Integer.valueOf(this.c));
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AudioFormat[sampleRate=");
        sb.append(this.a);
        sb.append(", channelCount=");
        sb.append(this.b);
        sb.append(", encoding=");
        return android.support.v4.media.session.a.r(sb, this.c, "]");
    }
}
