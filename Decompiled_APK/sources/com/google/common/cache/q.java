package com.google.common.cache;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3496m4;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class q extends AbstractC3496m4 implements Serializable {
    public final x b;
    public final x c;
    public final com.google.common.base.f d;
    public final com.google.common.base.f e;
    public final long f;
    public final long g;
    public final long h;
    public final EnumC3911e i;
    public final int j;
    public final EnumC3910d k;
    public final com.google.common.base.q l;
    public transient p m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(I i) {
        super(false);
        x xVar = i.g;
        this.b = xVar;
        this.c = i.h;
        this.d = i.e;
        this.e = i.f;
        this.f = i.l;
        this.g = i.k;
        this.h = i.i;
        this.i = i.j;
        this.j = i.d;
        this.k = i.n;
        com.google.common.base.p pVar = com.google.common.base.q.a;
        com.google.common.base.q qVar = i.o;
        this.l = (qVar == pVar || qVar == C3912f.o) ? null : qVar;
    }

    private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
        objectInputStream.defaultReadObject();
        C3912f c3912fD = C3912f.d();
        x xVar = c3912fD.f;
        com.google.common.base.b.g("Key strength was already set to %s", xVar, xVar == null);
        x xVar2 = this.b;
        xVar2.getClass();
        c3912fD.f = xVar2;
        x xVar3 = c3912fD.g;
        com.google.common.base.b.g("Value strength was already set to %s", xVar3, xVar3 == null);
        x xVar4 = this.c;
        xVar4.getClass();
        c3912fD.g = xVar4;
        com.google.common.base.f fVar = c3912fD.j;
        com.google.common.base.b.g("key equivalence was already set to %s", fVar, fVar == null);
        com.google.common.base.f fVar2 = this.d;
        fVar2.getClass();
        c3912fD.j = fVar2;
        com.google.common.base.f fVar3 = c3912fD.k;
        com.google.common.base.b.g("value equivalence was already set to %s", fVar3, fVar3 == null);
        com.google.common.base.f fVar4 = this.e;
        fVar4.getClass();
        c3912fD.k = fVar4;
        int i = c3912fD.b;
        if (i != -1) {
            throw new IllegalStateException(com.google.common.base.b.j("concurrency level was already set to %s", Integer.valueOf(i)));
        }
        int i2 = this.j;
        com.google.common.base.b.b(i2 > 0);
        c3912fD.b = i2;
        if (c3912fD.l != null) {
            throw new IllegalStateException();
        }
        EnumC3910d enumC3910d = this.k;
        enumC3910d.getClass();
        c3912fD.l = enumC3910d;
        c3912fD.a = false;
        long j = this.f;
        if (j > 0) {
            c3912fD.b(j, TimeUnit.NANOSECONDS);
        }
        long j2 = this.g;
        if (j2 > 0) {
            TimeUnit timeUnit = TimeUnit.NANOSECONDS;
            long j3 = c3912fD.i;
            com.google.common.base.b.f("expireAfterAccess was already set to %s ns", j3, j3 == -1);
            if (!(j2 >= 0)) {
                throw new IllegalArgumentException(com.google.common.base.b.j("duration cannot be negative: %s %s", Long.valueOf(j2), timeUnit));
            }
            c3912fD.i = timeUnit.toNanos(j2);
        }
        EnumC3911e enumC3911e = EnumC3911e.a;
        long j4 = this.h;
        EnumC3911e enumC3911e2 = this.i;
        if (enumC3911e2 != enumC3911e) {
            if (c3912fD.e != null) {
                throw new IllegalStateException();
            }
            if (c3912fD.a) {
                long j5 = c3912fD.c;
                com.google.common.base.b.f("weigher can not be combined with maximum size (%s provided)", j5, j5 == -1);
            }
            enumC3911e2.getClass();
            c3912fD.e = enumC3911e2;
            if (j4 != -1) {
                long j6 = c3912fD.d;
                com.google.common.base.b.f("maximum weight was already set to %s", j6, j6 == -1);
                long j7 = c3912fD.c;
                com.google.common.base.b.f("maximum size was already set to %s", j7, j7 == -1);
                if (!(j4 >= 0)) {
                    throw new IllegalArgumentException("maximum weight must not be negative");
                }
                c3912fD.d = j4;
            }
        } else if (j4 != -1) {
            c3912fD.c(j4);
        }
        com.google.common.base.q qVar = this.l;
        if (qVar != null) {
            if (c3912fD.m != null) {
                throw new IllegalStateException();
            }
            c3912fD.m = qVar;
        }
        this.m = c3912fD.a();
    }

    private Object readResolve() {
        return this.m;
    }
}
