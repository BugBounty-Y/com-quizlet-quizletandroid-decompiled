package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.gf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2100gf {
    public final Bu a;
    public final ArrayList b = new ArrayList();
    public ByteBuffer[] c = new ByteBuffer[0];
    public boolean d;

    public C2100gf(Bu bu) {
        this.a = bu;
        C2229jf c2229jf = C2229jf.e;
        this.d = false;
    }

    public final C2229jf a(C2229jf c2229jf) {
        if (c2229jf.equals(C2229jf.e)) {
            throw new zzcm("Unhandled input format:", c2229jf);
        }
        int i = 0;
        while (true) {
            Bu bu = this.a;
            if (i >= bu.d) {
                return c2229jf;
            }
            InterfaceC1688Ef interfaceC1688Ef = (InterfaceC1688Ef) bu.get(i);
            C2229jf c2229jfB = interfaceC1688Ef.b(c2229jf);
            if (interfaceC1688Ef.h()) {
                AbstractC1795We.L(!c2229jfB.equals(r0));
                c2229jf = c2229jfB;
            }
            i++;
        }
    }

    public final void b() {
        ArrayList arrayList = this.b;
        arrayList.clear();
        this.d = false;
        int i = 0;
        while (true) {
            Bu bu = this.a;
            if (i >= bu.d) {
                break;
            }
            InterfaceC1688Ef interfaceC1688Ef = (InterfaceC1688Ef) bu.get(i);
            interfaceC1688Ef.a();
            if (interfaceC1688Ef.h()) {
                arrayList.add(interfaceC1688Ef);
            }
            i++;
        }
        this.c = new ByteBuffer[arrayList.size()];
        for (int i2 = 0; i2 <= e(); i2++) {
            this.c[i2] = ((InterfaceC1688Ef) arrayList.get(i2)).zzb();
        }
    }

    public final boolean c() {
        return this.d && ((InterfaceC1688Ef) this.b.get(e())).g() && !this.c[e()].hasRemaining();
    }

    public final boolean d() {
        return !this.b.isEmpty();
    }

    public final int e() {
        return this.c.length - 1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C2100gf) {
            Bu bu = this.a;
            int i = bu.d;
            Bu bu2 = ((C2100gf) obj).a;
            if (i == bu2.d) {
                for (int i2 = 0; i2 < bu.d; i2++) {
                    if (bu.get(i2) == bu2.get(i2)) {
                    }
                }
                return true;
            }
        }
        return false;
    }

    public final void f(ByteBuffer byteBuffer) {
        boolean z;
        do {
            int i = 0;
            z = false;
            while (i <= e()) {
                if (!this.c[i].hasRemaining()) {
                    ArrayList arrayList = this.b;
                    InterfaceC1688Ef interfaceC1688Ef = (InterfaceC1688Ef) arrayList.get(i);
                    if (!interfaceC1688Ef.g()) {
                        ByteBuffer byteBuffer2 = i > 0 ? this.c[i - 1] : byteBuffer.hasRemaining() ? byteBuffer : InterfaceC1688Ef.a;
                        long jRemaining = byteBuffer2.remaining();
                        interfaceC1688Ef.c(byteBuffer2);
                        this.c[i] = interfaceC1688Ef.zzb();
                        boolean z2 = true;
                        if (jRemaining - byteBuffer2.remaining() <= 0 && !this.c[i].hasRemaining()) {
                            z2 = false;
                        }
                        z |= z2;
                    } else if (!this.c[i].hasRemaining() && i < e()) {
                        ((InterfaceC1688Ef) arrayList.get(i + 1)).j();
                    }
                }
                i++;
            }
        } while (z);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
