package androidx.emoji2.text;

import java.nio.ByteBuffer;

/* loaded from: classes.dex */
public final class s {
    public int a = 1;
    public final v b;
    public v c;
    public v d;
    public int e;
    public int f;

    public s(v vVar) {
        this.b = vVar;
        this.c = vVar;
    }

    public final void a() {
        this.a = 1;
        this.c = this.b;
        this.f = 0;
    }

    public final boolean b() {
        androidx.emoji2.text.flatbuffer.a aVarB = this.c.b.b();
        int iA = aVarB.a(6);
        return !(iA == 0 || ((ByteBuffer) aVarB.d).get(iA + aVarB.a) == 0) || this.e == 65039;
    }
}
