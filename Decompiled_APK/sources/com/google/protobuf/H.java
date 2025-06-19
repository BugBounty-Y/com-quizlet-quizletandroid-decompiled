package com.google.protobuf;

import java.util.List;

/* loaded from: classes2.dex */
public final class H extends I {
    @Override // com.google.protobuf.I
    public final void a(long j, Object obj) {
        AbstractC4006b abstractC4006b = (AbstractC4006b) ((B) t0.c.i(j, obj));
        if (abstractC4006b.a) {
            abstractC4006b.a = false;
        }
    }

    @Override // com.google.protobuf.I
    public final void b(long j, Object obj, Object obj2) {
        s0 s0Var = t0.c;
        B bQ = (B) s0Var.i(j, obj);
        B b = (B) s0Var.i(j, obj2);
        int size = bQ.size();
        int size2 = b.size();
        if (size > 0 && size2 > 0) {
            if (!((AbstractC4006b) bQ).a) {
                bQ = bQ.q(size2 + size);
            }
            bQ.addAll(b);
        }
        if (size > 0) {
            b = bQ;
        }
        t0.p(j, obj, b);
    }

    @Override // com.google.protobuf.I
    public final List c(long j, Object obj) {
        B b = (B) t0.c.i(j, obj);
        if (((AbstractC4006b) b).a) {
            return b;
        }
        int size = b.size();
        B bQ = b.q(size == 0 ? 10 : size * 2);
        t0.p(j, obj, bQ);
        return bQ;
    }
}
