package androidx.emoji2.text;

import java.nio.ByteBuffer;

/* loaded from: classes.dex */
public final class y {
    public static final ThreadLocal d = new ThreadLocal();
    public final int a;
    public final com.quizlet.data.repository.explanations.textbook.a b;
    public volatile int c = 0;

    public y(com.quizlet.data.repository.explanations.textbook.a aVar, int i) {
        this.b = aVar;
        this.a = i;
    }

    public final int a(int i) {
        androidx.emoji2.text.flatbuffer.a aVarB = b();
        int iA = aVarB.a(16);
        if (iA == 0) {
            return 0;
        }
        ByteBuffer byteBuffer = (ByteBuffer) aVarB.d;
        int i2 = iA + aVarB.a;
        return byteBuffer.getInt((i * 4) + byteBuffer.getInt(i2) + i2 + 4);
    }

    public final androidx.emoji2.text.flatbuffer.a b() {
        ThreadLocal threadLocal = d;
        androidx.emoji2.text.flatbuffer.a aVar = (androidx.emoji2.text.flatbuffer.a) threadLocal.get();
        if (aVar == null) {
            aVar = new androidx.emoji2.text.flatbuffer.a();
            threadLocal.set(aVar);
        }
        androidx.emoji2.text.flatbuffer.b bVar = (androidx.emoji2.text.flatbuffer.b) this.b.a;
        int iA = bVar.a(6);
        if (iA != 0) {
            int i = iA + bVar.a;
            int i2 = (this.a * 4) + ((ByteBuffer) bVar.d).getInt(i) + i + 4;
            int i3 = ((ByteBuffer) bVar.d).getInt(i2) + i2;
            ByteBuffer byteBuffer = (ByteBuffer) bVar.d;
            aVar.d = byteBuffer;
            if (byteBuffer != null) {
                aVar.a = i3;
                int i4 = i3 - byteBuffer.getInt(i3);
                aVar.b = i4;
                aVar.c = ((ByteBuffer) aVar.d).getShort(i4);
                return aVar;
            }
            aVar.a = 0;
            aVar.b = 0;
            aVar.c = 0;
        }
        return aVar;
    }

    public final String toString() {
        int i;
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString());
        sb.append(", id:");
        androidx.emoji2.text.flatbuffer.a aVarB = b();
        int iA = aVarB.a(4);
        sb.append(Integer.toHexString(iA != 0 ? ((ByteBuffer) aVarB.d).getInt(iA + aVarB.a) : 0));
        sb.append(", codepoints:");
        androidx.emoji2.text.flatbuffer.a aVarB2 = b();
        int iA2 = aVarB2.a(16);
        if (iA2 != 0) {
            int i2 = iA2 + aVarB2.a;
            i = ((ByteBuffer) aVarB2.d).getInt(((ByteBuffer) aVarB2.d).getInt(i2) + i2);
        } else {
            i = 0;
        }
        for (int i3 = 0; i3 < i; i3++) {
            sb.append(Integer.toHexString(a(i3)));
            sb.append(" ");
        }
        return sb.toString();
    }
}
