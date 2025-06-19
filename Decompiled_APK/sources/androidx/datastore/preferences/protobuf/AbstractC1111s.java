package androidx.datastore.preferences.protobuf;

/* renamed from: androidx.datastore.preferences.protobuf.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1111s implements Cloneable {
    public final AbstractC1113u a;
    public AbstractC1113u b;

    public AbstractC1111s(AbstractC1113u abstractC1113u) {
        this.a = abstractC1113u;
        if (abstractC1113u.g()) {
            throw new IllegalArgumentException("Default instance must be immutable.");
        }
        this.b = abstractC1113u.i();
    }

    public final AbstractC1113u b() {
        AbstractC1113u abstractC1113uC = c();
        abstractC1113uC.getClass();
        if (AbstractC1113u.f(abstractC1113uC, true)) {
            return abstractC1113uC;
        }
        throw new UninitializedMessageException();
    }

    public final AbstractC1113u c() {
        if (!this.b.g()) {
            return this.b;
        }
        AbstractC1113u abstractC1113u = this.b;
        abstractC1113u.getClass();
        Q q = Q.c;
        q.getClass();
        q.a(abstractC1113u.getClass()).b(abstractC1113u);
        abstractC1113u.h();
        return this.b;
    }

    public final Object clone() {
        AbstractC1111s abstractC1111s = (AbstractC1111s) this.a.c(5);
        abstractC1111s.b = c();
        return abstractC1111s;
    }

    public final void d() {
        if (this.b.g()) {
            return;
        }
        AbstractC1113u abstractC1113uI = this.a.i();
        AbstractC1113u abstractC1113u = this.b;
        Q q = Q.c;
        q.getClass();
        q.a(abstractC1113uI.getClass()).a(abstractC1113uI, abstractC1113u);
        this.b = abstractC1113uI;
    }
}
