package com.google.android.gms.internal.ads;

import java.io.EOFException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public abstract class M3 {
    public static final Logger b = Logger.getLogger(M3.class.getName());
    public final androidx.camera.core.impl.utils.executor.b a = new androidx.camera.core.impl.utils.executor.b(8);

    /* JADX WARN: Multi-variable type inference failed */
    public final O3 a(C1722Kd c1722Kd, AbstractC2692uC abstractC2692uC) throws EOFException {
        int iA;
        ByteBuffer byteBuffer;
        long jLimit;
        O3 r3;
        O3 o3;
        long jD = c1722Kd.d();
        androidx.camera.core.impl.utils.executor.b bVar = this.a;
        ((ByteBuffer) bVar.get()).rewind().limit(8);
        do {
            iA = c1722Kd.a((ByteBuffer) bVar.get());
            byteBuffer = c1722Kd.a;
            if (iA == 8) {
                ((ByteBuffer) bVar.get()).rewind();
                long jC = AbstractC2096gb.C((ByteBuffer) bVar.get());
                if (jC < 8 && jC > 1) {
                    Level level = Level.SEVERE;
                    StringBuilder sb = new StringBuilder(80);
                    sb.append("Plausibility check failed: size < 8 (size = ");
                    sb.append(jC);
                    sb.append("). Stop parsing!");
                    b.logp(level, "com.coremedia.iso.AbstractBoxParser", "parseBox", sb.toString());
                    return null;
                }
                byte[] bArr = new byte[4];
                ((ByteBuffer) bVar.get()).get(bArr);
                try {
                    String str = new String(bArr, "ISO-8859-1");
                    if (jC == 1) {
                        ((ByteBuffer) bVar.get()).limit(16);
                        c1722Kd.a((ByteBuffer) bVar.get());
                        ((ByteBuffer) bVar.get()).position(8);
                        jLimit = AbstractC2096gb.H((ByteBuffer) bVar.get()) - 16;
                    } else {
                        jLimit = jC == 0 ? byteBuffer.limit() - c1722Kd.d() : jC - 8;
                    }
                    if ("uuid".equals(str)) {
                        ((ByteBuffer) bVar.get()).limit(((ByteBuffer) bVar.get()).limit() + 16);
                        c1722Kd.a((ByteBuffer) bVar.get());
                        byte[] bArr2 = new byte[16];
                        for (int iPosition = ((ByteBuffer) bVar.get()).position() - 16; iPosition < ((ByteBuffer) bVar.get()).position(); iPosition++) {
                            bArr2[iPosition - (((ByteBuffer) bVar.get()).position() - 16)] = ((ByteBuffer) bVar.get()).get(iPosition);
                        }
                        jLimit -= 16;
                    }
                    long j = jLimit;
                    if (abstractC2692uC instanceof O3) {
                    }
                    if ("moov".equals(str)) {
                        r3 = new P3();
                    } else {
                        if ("mvhd".equals(str)) {
                            Q3 q3 = new Q3("mvhd");
                            q3.n = 1.0d;
                            q3.o = 1.0f;
                            q3.p = C2864yC.j;
                            o3 = q3;
                            ((ByteBuffer) bVar.get()).rewind();
                            o3.a(c1722Kd, (ByteBuffer) bVar.get(), j, this);
                            return o3;
                        }
                        r3 = new R3(str, 0);
                    }
                    o3 = r3;
                    ((ByteBuffer) bVar.get()).rewind();
                    o3.a(c1722Kd, (ByteBuffer) bVar.get(), j, this);
                    return o3;
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException(e);
                }
            }
        } while (iA >= 0);
        byteBuffer.position((int) jD);
        throw new EOFException();
    }
}
