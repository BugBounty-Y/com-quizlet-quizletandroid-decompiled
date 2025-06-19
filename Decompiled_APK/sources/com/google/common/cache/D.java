package com.google.common.cache;

import java.lang.ref.ReferenceQueue;

/* loaded from: classes2.dex */
public final class D extends F {
    public final /* synthetic */ int d;
    public volatile long e;
    public J f;
    public J g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ D(ReferenceQueue referenceQueue, Object obj, int i, J j, int i2) {
        super(referenceQueue, obj, i, j);
        this.d = i2;
    }

    @Override // com.google.common.cache.F, com.google.common.cache.J
    public J a() {
        switch (this.d) {
            case 0:
                return this.g;
            default:
                return super.a();
        }
    }

    @Override // com.google.common.cache.F, com.google.common.cache.J
    public long c() {
        switch (this.d) {
            case 1:
                return this.e;
            default:
                return super.c();
        }
    }

    @Override // com.google.common.cache.F, com.google.common.cache.J
    public void d(long j) {
        switch (this.d) {
            case 0:
                this.e = j;
                break;
            default:
                super.d(j);
                break;
        }
    }

    @Override // com.google.common.cache.F, com.google.common.cache.J
    public J e() {
        switch (this.d) {
            case 1:
                return this.f;
            default:
                return super.e();
        }
    }

    @Override // com.google.common.cache.F, com.google.common.cache.J
    public long f() {
        switch (this.d) {
            case 0:
                return this.e;
            default:
                return super.f();
        }
    }

    @Override // com.google.common.cache.F, com.google.common.cache.J
    public void g(long j) {
        switch (this.d) {
            case 1:
                this.e = j;
                break;
            default:
                super.g(j);
                break;
        }
    }

    @Override // com.google.common.cache.F, com.google.common.cache.J
    public J j() {
        switch (this.d) {
            case 0:
                return this.f;
            default:
                return super.j();
        }
    }

    @Override // com.google.common.cache.F, com.google.common.cache.J
    public void k(J j) {
        switch (this.d) {
            case 0:
                this.f = j;
                break;
            default:
                super.k(j);
                break;
        }
    }

    @Override // com.google.common.cache.F, com.google.common.cache.J
    public void l(J j) {
        switch (this.d) {
            case 1:
                this.f = j;
                break;
            default:
                super.l(j);
                break;
        }
    }

    @Override // com.google.common.cache.F, com.google.common.cache.J
    public void m(J j) {
        switch (this.d) {
            case 1:
                this.g = j;
                break;
            default:
                super.m(j);
                break;
        }
    }

    @Override // com.google.common.cache.F, com.google.common.cache.J
    public void n(J j) {
        switch (this.d) {
            case 0:
                this.g = j;
                break;
            default:
                super.n(j);
                break;
        }
    }

    @Override // com.google.common.cache.F, com.google.common.cache.J
    public J o() {
        switch (this.d) {
            case 1:
                return this.g;
            default:
                return super.o();
        }
    }
}
