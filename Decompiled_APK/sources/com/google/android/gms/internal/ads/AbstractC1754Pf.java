package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/* renamed from: com.google.android.gms.internal.ads.Pf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1754Pf implements InterfaceC1688Ef {
    public C2229jf b;
    public C2229jf c;
    public C2229jf d;
    public C2229jf e;
    public ByteBuffer f;
    public ByteBuffer g;
    public boolean h;

    public AbstractC1754Pf() {
        ByteBuffer byteBuffer = InterfaceC1688Ef.a;
        this.f = byteBuffer;
        this.g = byteBuffer;
        C2229jf c2229jf = C2229jf.e;
        this.d = c2229jf;
        this.e = c2229jf;
        this.b = c2229jf;
        this.c = c2229jf;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final void a() {
        this.g = InterfaceC1688Ef.a;
        this.h = false;
        this.b = this.d;
        this.c = this.e;
        i();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final C2229jf b(C2229jf c2229jf) {
        this.d = c2229jf;
        this.e = d(c2229jf);
        return h() ? this.e : C2229jf.e;
    }

    public abstract C2229jf d(C2229jf c2229jf);

    public final ByteBuffer e(int i) {
        if (this.f.capacity() < i) {
            this.f = ByteBuffer.allocateDirect(i).order(ByteOrder.nativeOrder());
        } else {
            this.f.clear();
        }
        ByteBuffer byteBuffer = this.f;
        this.g = byteBuffer;
        return byteBuffer;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final void f() {
        a();
        this.f = InterfaceC1688Ef.a;
        C2229jf c2229jf = C2229jf.e;
        this.d = c2229jf;
        this.e = c2229jf;
        this.b = c2229jf;
        this.c = c2229jf;
        l();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public boolean g() {
        return this.h && this.g == InterfaceC1688Ef.a;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public boolean h() {
        return this.e != C2229jf.e;
    }

    public void i() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final void j() {
        this.h = true;
        k();
    }

    public void k() {
    }

    public void l() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public ByteBuffer zzb() {
        ByteBuffer byteBuffer = this.g;
        this.g = InterfaceC1688Ef.a;
        return byteBuffer;
    }
}
