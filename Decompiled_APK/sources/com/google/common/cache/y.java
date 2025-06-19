package com.google.common.cache;

/* loaded from: classes2.dex */
public final class y extends A {
    public final /* synthetic */ int e;
    public volatile long f;
    public J g;
    public J h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ y(Object obj, int i, J j, int i2) {
        super(obj, i, j);
        this.e = i2;
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public J a() {
        switch (this.e) {
            case 0:
                return this.h;
            default:
                return super.a();
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public long c() {
        switch (this.e) {
            case 1:
                return this.f;
            default:
                return super.c();
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public void d(long j) {
        switch (this.e) {
            case 0:
                this.f = j;
                break;
            default:
                super.d(j);
                break;
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public J e() {
        switch (this.e) {
            case 1:
                return this.g;
            default:
                return super.e();
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public long f() {
        switch (this.e) {
            case 0:
                return this.f;
            default:
                return super.f();
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public void g(long j) {
        switch (this.e) {
            case 1:
                this.f = j;
                break;
            default:
                super.g(j);
                break;
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public J j() {
        switch (this.e) {
            case 0:
                return this.g;
            default:
                return super.j();
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public void k(J j) {
        switch (this.e) {
            case 0:
                this.g = j;
                break;
            default:
                super.k(j);
                break;
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public void l(J j) {
        switch (this.e) {
            case 1:
                this.g = j;
                break;
            default:
                super.l(j);
                break;
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public void m(J j) {
        switch (this.e) {
            case 1:
                this.h = j;
                break;
            default:
                super.m(j);
                break;
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public void n(J j) {
        switch (this.e) {
            case 0:
                this.h = j;
                break;
            default:
                super.n(j);
                break;
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public J o() {
        switch (this.e) {
            case 1:
                return this.h;
            default:
                return super.o();
        }
    }
}
