package com.google.android.gms.internal.play_billing;

import java.nio.charset.Charset;

/* renamed from: com.google.android.gms.internal.play_billing.m1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3817m1 implements InterfaceC3826p1 {
    public static final C3781a1 b = new C3781a1(3);
    public final Object a;

    public C3817m1(InterfaceC3826p1... interfaceC3826p1Arr) {
        this.a = interfaceC3826p1Arr;
    }

    public void a(int i, Object obj, InterfaceC3852y1 interfaceC3852y1) throws zzgp {
        V0 v0 = (V0) this.a;
        v0.Y(i, 3);
        interfaceC3852y1.h((P0) obj, v0.b);
        v0.Y(i, 4);
    }

    public void b(int i, Object obj, InterfaceC3852y1 interfaceC3852y1) throws zzgp {
        P0 p0 = (P0) obj;
        V0 v0 = (V0) this.a;
        v0.a0((i << 3) | 2);
        v0.a0(p0.a(interfaceC3852y1));
        interfaceC3852y1.h(p0, v0.b);
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3826p1
    public C3849x1 c(Class cls) {
        for (int i = 0; i < 2; i++) {
            InterfaceC3826p1 interfaceC3826p1 = ((InterfaceC3826p1[]) this.a)[i];
            if (interfaceC3826p1.d(cls)) {
                return interfaceC3826p1.c(cls);
            }
        }
        throw new UnsupportedOperationException("No factory is available for message type: ".concat(cls.getName()));
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3826p1
    public boolean d(Class cls) {
        for (int i = 0; i < 2; i++) {
            if (((InterfaceC3826p1[]) this.a)[i].d(cls)) {
                return true;
            }
        }
        return false;
    }

    public C3817m1() {
        C3843v1 c3843v1 = C3843v1.c;
        C3817m1 c3817m1 = new C3817m1(C3781a1.b, b);
        Charset charset = AbstractC3802h1.a;
        this.a = c3817m1;
    }

    public C3817m1(V0 v0) {
        Charset charset = AbstractC3802h1.a;
        this.a = v0;
        v0.b = this;
    }
}
