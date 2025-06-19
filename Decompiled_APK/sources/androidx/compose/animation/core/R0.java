package androidx.compose.animation.core;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class R0 {
    public final F a;
    public AbstractC0267t b;
    public AbstractC0267t c;
    public AbstractC0267t d;
    public final float e;

    public R0(F f) {
        this.a = f;
        this.e = f.a();
    }

    public final AbstractC0267t a(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2) {
        if (this.c == null) {
            this.c = abstractC0267t.c();
        }
        AbstractC0267t abstractC0267t3 = this.c;
        if (abstractC0267t3 == null) {
            Intrinsics.m("velocityVector");
            throw null;
        }
        int iB = abstractC0267t3.b();
        for (int i = 0; i < iB; i++) {
            AbstractC0267t abstractC0267t4 = this.c;
            if (abstractC0267t4 == null) {
                Intrinsics.m("velocityVector");
                throw null;
            }
            abstractC0267t.getClass();
            abstractC0267t4.e(this.a.v(j, abstractC0267t2.a(i)), i);
        }
        AbstractC0267t abstractC0267t5 = this.c;
        if (abstractC0267t5 != null) {
            return abstractC0267t5;
        }
        Intrinsics.m("velocityVector");
        throw null;
    }
}
