package com.google.android.gms.internal.ads;

import java.io.IOException;
import java.nio.ByteBuffer;

/* renamed from: com.google.android.gms.internal.ads.tC, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2649tC implements O3 {
    public static final AbstractC2457os h = AbstractC2457os.o(AbstractC2649tC.class);
    public final String a;
    public ByteBuffer d;
    public long e;
    public C1722Kd g;
    public long f = -1;
    public boolean c = true;
    public boolean b = true;

    public AbstractC2649tC(String str) {
        this.a = str;
    }

    @Override // com.google.android.gms.internal.ads.O3
    public final void a(C1722Kd c1722Kd, ByteBuffer byteBuffer, long j, M3 m3) {
        this.e = c1722Kd.d();
        byteBuffer.remaining();
        this.f = j;
        this.g = c1722Kd;
        c1722Kd.a.position((int) (c1722Kd.d() + j));
        this.c = false;
        this.b = false;
        d();
    }

    public final synchronized void b() {
        try {
            if (this.c) {
                return;
            }
            try {
                AbstractC2457os abstractC2457os = h;
                String str = this.a;
                abstractC2457os.i(str.length() != 0 ? "mem mapping ".concat(str) : new String("mem mapping "));
                C1722Kd c1722Kd = this.g;
                long j = this.e;
                long j2 = this.f;
                ByteBuffer byteBuffer = c1722Kd.a;
                int iPosition = byteBuffer.position();
                byteBuffer.position((int) j);
                ByteBuffer byteBufferSlice = byteBuffer.slice();
                byteBufferSlice.limit((int) j2);
                byteBuffer.position(iPosition);
                this.d = byteBufferSlice;
                this.c = true;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public abstract void c(ByteBuffer byteBuffer);

    public final synchronized void d() {
        try {
            b();
            AbstractC2457os abstractC2457os = h;
            String str = this.a;
            abstractC2457os.i(str.length() != 0 ? "parsing details of ".concat(str) : new String("parsing details of "));
            ByteBuffer byteBuffer = this.d;
            if (byteBuffer != null) {
                this.b = true;
                byteBuffer.rewind();
                c(byteBuffer);
                if (byteBuffer.remaining() > 0) {
                    byteBuffer.slice();
                }
                this.d = null;
            }
        } catch (Throwable th) {
            throw th;
        }
    }
}
