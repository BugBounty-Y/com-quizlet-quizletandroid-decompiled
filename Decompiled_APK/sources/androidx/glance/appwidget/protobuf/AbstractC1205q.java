package androidx.glance.appwidget.protobuf;

/* renamed from: androidx.glance.appwidget.protobuf.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1205q implements Cloneable {
    public final AbstractC1206s a;
    public AbstractC1206s b;

    public AbstractC1205q(AbstractC1206s abstractC1206s) {
        this.a = abstractC1206s;
        if (abstractC1206s.f()) {
            throw new IllegalArgumentException("Default instance must be immutable.");
        }
        this.b = abstractC1206s.h();
    }

    public static void e(Object obj, Object obj2) {
        L l = L.c;
        l.getClass();
        l.a(obj.getClass()).a(obj, obj2);
    }

    public final AbstractC1206s b() {
        AbstractC1206s abstractC1206sC = c();
        abstractC1206sC.getClass();
        if (AbstractC1206s.e(abstractC1206sC, true)) {
            return abstractC1206sC;
        }
        throw new UninitializedMessageException();
    }

    public final AbstractC1206s c() {
        if (!this.b.f()) {
            return this.b;
        }
        AbstractC1206s abstractC1206s = this.b;
        abstractC1206s.getClass();
        L l = L.c;
        l.getClass();
        l.a(abstractC1206s.getClass()).b(abstractC1206s);
        abstractC1206s.g();
        return this.b;
    }

    public final Object clone() {
        AbstractC1205q abstractC1205q = (AbstractC1205q) this.a.b(5);
        abstractC1205q.b = c();
        return abstractC1205q;
    }

    public final void d() {
        if (this.b.f()) {
            return;
        }
        AbstractC1206s abstractC1206sH = this.a.h();
        e(abstractC1206sH, this.b);
        this.b = abstractC1206sH;
    }
}
