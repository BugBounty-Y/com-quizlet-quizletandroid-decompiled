package com.google.common.cache;

import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

/* renamed from: com.google.common.cache.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3912f {
    public static final com.google.common.base.o n = new com.google.common.base.o(new C3907a());
    public static final C3908b o = new C3908b();
    public boolean a;
    public int b;
    public long c;
    public long d;
    public EnumC3911e e;
    public x f;
    public x g;
    public long h;
    public long i;
    public com.google.common.base.f j;
    public com.google.common.base.f k;
    public EnumC3910d l;
    public com.google.common.base.q m;

    public static C3912f d() {
        C3912f c3912f = new C3912f();
        c3912f.a = true;
        c3912f.b = -1;
        c3912f.c = -1L;
        c3912f.d = -1L;
        c3912f.h = -1L;
        c3912f.i = -1L;
        return c3912f;
    }

    public final p a() {
        if (this.e == null) {
            com.google.common.base.b.h("maximumWeight requires weigher", this.d == -1);
        } else if (this.a) {
            com.google.common.base.b.h("weigher requires maximumWeight", this.d != -1);
        } else if (this.d == -1) {
            AbstractC3909c.a.log(Level.WARNING, "ignoring weigher specified without maximumWeight");
        }
        return new p(this);
    }

    public final void b(long j, TimeUnit timeUnit) {
        long j2 = this.h;
        com.google.common.base.b.f("expireAfterWrite was already set to %s ns", j2, j2 == -1);
        if (!(j >= 0)) {
            throw new IllegalArgumentException(com.google.common.base.b.j("duration cannot be negative: %s %s", Long.valueOf(j), timeUnit));
        }
        this.h = timeUnit.toNanos(j);
    }

    public final void c(long j) {
        long j2 = this.c;
        com.google.common.base.b.f("maximum size was already set to %s", j2, j2 == -1);
        long j3 = this.d;
        com.google.common.base.b.f("maximum weight was already set to %s", j3, j3 == -1);
        com.google.common.base.b.h("maximum size can not be combined with weigher", this.e == null);
        if (!(j >= 0)) {
            throw new IllegalArgumentException("maximum size must not be negative");
        }
        this.c = j;
    }

    public final String toString() {
        com.quizlet.data.repository.set.f fVar = new com.quizlet.data.repository.set.f(C3912f.class.getSimpleName(), 8);
        int i = this.b;
        if (i != -1) {
            String strValueOf = String.valueOf(i);
            com.google.common.base.h hVar = new com.google.common.base.h();
            ((com.quizlet.data.repository.login.a) fVar.d).c = hVar;
            fVar.d = hVar;
            hVar.b = strValueOf;
            hVar.a = "concurrencyLevel";
        }
        long j = this.c;
        if (j != -1) {
            String strValueOf2 = String.valueOf(j);
            com.google.common.base.h hVar2 = new com.google.common.base.h();
            ((com.quizlet.data.repository.login.a) fVar.d).c = hVar2;
            fVar.d = hVar2;
            hVar2.b = strValueOf2;
            hVar2.a = "maximumSize";
        }
        long j2 = this.d;
        if (j2 != -1) {
            String strValueOf3 = String.valueOf(j2);
            com.google.common.base.h hVar3 = new com.google.common.base.h();
            ((com.quizlet.data.repository.login.a) fVar.d).c = hVar3;
            fVar.d = hVar3;
            hVar3.b = strValueOf3;
            hVar3.a = "maximumWeight";
        }
        if (this.h != -1) {
            String strG = android.support.v4.media.session.a.g(this.h, "ns", new StringBuilder());
            com.quizlet.data.repository.login.a aVar = new com.quizlet.data.repository.login.a();
            ((com.quizlet.data.repository.login.a) fVar.d).c = aVar;
            fVar.d = aVar;
            aVar.b = strG;
            aVar.a = "expireAfterWrite";
        }
        if (this.i != -1) {
            String strG2 = android.support.v4.media.session.a.g(this.i, "ns", new StringBuilder());
            com.quizlet.data.repository.login.a aVar2 = new com.quizlet.data.repository.login.a();
            ((com.quizlet.data.repository.login.a) fVar.d).c = aVar2;
            fVar.d = aVar2;
            aVar2.b = strG2;
            aVar2.a = "expireAfterAccess";
        }
        x xVar = this.f;
        if (xVar != null) {
            String strK = com.google.common.base.b.k(xVar.toString());
            com.quizlet.data.repository.login.a aVar3 = new com.quizlet.data.repository.login.a();
            ((com.quizlet.data.repository.login.a) fVar.d).c = aVar3;
            fVar.d = aVar3;
            aVar3.b = strK;
            aVar3.a = "keyStrength";
        }
        x xVar2 = this.g;
        if (xVar2 != null) {
            String strK2 = com.google.common.base.b.k(xVar2.toString());
            com.quizlet.data.repository.login.a aVar4 = new com.quizlet.data.repository.login.a();
            ((com.quizlet.data.repository.login.a) fVar.d).c = aVar4;
            fVar.d = aVar4;
            aVar4.b = strK2;
            aVar4.a = "valueStrength";
        }
        if (this.j != null) {
            com.quizlet.data.repository.login.a aVar5 = new com.quizlet.data.repository.login.a();
            ((com.quizlet.data.repository.login.a) fVar.d).c = aVar5;
            fVar.d = aVar5;
            aVar5.b = "keyEquivalence";
        }
        if (this.k != null) {
            com.quizlet.data.repository.login.a aVar6 = new com.quizlet.data.repository.login.a();
            ((com.quizlet.data.repository.login.a) fVar.d).c = aVar6;
            fVar.d = aVar6;
            aVar6.b = "valueEquivalence";
        }
        if (this.l != null) {
            com.quizlet.data.repository.login.a aVar7 = new com.quizlet.data.repository.login.a();
            ((com.quizlet.data.repository.login.a) fVar.d).c = aVar7;
            fVar.d = aVar7;
            aVar7.b = "removalListener";
        }
        return fVar.toString();
    }
}
