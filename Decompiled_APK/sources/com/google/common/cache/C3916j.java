package com.google.common.cache;

/* renamed from: com.google.common.cache.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3916j extends AbstractC3915i {
    public final /* synthetic */ int a;
    public J b;
    public J c;

    private final void i(long j) {
    }

    private final void q(long j) {
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public J a() {
        switch (this.a) {
            case 0:
                return this.c;
            default:
                return super.a();
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public long c() {
        switch (this.a) {
            case 1:
                return Long.MAX_VALUE;
            default:
                return super.c();
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public void d(long j) {
        switch (this.a) {
            case 0:
                break;
            default:
                super.d(j);
                break;
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public J e() {
        switch (this.a) {
            case 1:
                return this.b;
            default:
                return super.e();
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public long f() {
        switch (this.a) {
            case 0:
                return Long.MAX_VALUE;
            default:
                return super.f();
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public void g(long j) {
        switch (this.a) {
            case 1:
                break;
            default:
                super.g(j);
                break;
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public J j() {
        switch (this.a) {
            case 0:
                return this.b;
            default:
                return super.j();
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public void k(J j) {
        switch (this.a) {
            case 0:
                this.b = j;
                break;
            default:
                super.k(j);
                break;
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public void l(J j) {
        switch (this.a) {
            case 1:
                this.b = j;
                break;
            default:
                super.l(j);
                break;
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public void m(J j) {
        switch (this.a) {
            case 1:
                this.c = j;
                break;
            default:
                super.m(j);
                break;
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public void n(J j) {
        switch (this.a) {
            case 0:
                this.c = j;
                break;
            default:
                super.n(j);
                break;
        }
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public J o() {
        switch (this.a) {
            case 1:
                return this.c;
            default:
                return super.o();
        }
    }
}
