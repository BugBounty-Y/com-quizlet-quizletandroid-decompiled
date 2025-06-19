package com.google.protobuf;

/* renamed from: com.google.protobuf.t, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC4025t implements Cloneable {
    public final AbstractC4027v a;
    public AbstractC4027v b;

    public AbstractC4025t(AbstractC4027v abstractC4027v) {
        this.a = abstractC4027v;
        if (abstractC4027v.p()) {
            throw new IllegalArgumentException("Default instance must be immutable.");
        }
        this.b = abstractC4027v.s();
    }

    public static void l(Object obj, Object obj2) {
        Z z = Z.c;
        z.getClass();
        z.a(obj.getClass()).a(obj, obj2);
    }

    public final Object clone() {
        AbstractC4025t abstractC4025t = (AbstractC4025t) this.a.l(5);
        abstractC4025t.b = i();
        return abstractC4025t;
    }

    public final AbstractC4027v h() {
        AbstractC4027v abstractC4027vI = i();
        abstractC4027vI.getClass();
        if (AbstractC4027v.o(abstractC4027vI, true)) {
            return abstractC4027vI;
        }
        throw new UninitializedMessageException();
    }

    public final AbstractC4027v i() {
        if (!this.b.p()) {
            return this.b;
        }
        AbstractC4027v abstractC4027v = this.b;
        abstractC4027v.getClass();
        Z z = Z.c;
        z.getClass();
        z.a(abstractC4027v.getClass()).b(abstractC4027v);
        abstractC4027v.q();
        return this.b;
    }

    public final void k() {
        if (this.b.p()) {
            return;
        }
        AbstractC4027v abstractC4027vS = this.a.s();
        l(abstractC4027vS, this.b);
        this.b = abstractC4027vS;
    }
}
