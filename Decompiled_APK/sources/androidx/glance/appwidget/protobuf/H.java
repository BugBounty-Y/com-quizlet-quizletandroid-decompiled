package androidx.glance.appwidget.protobuf;

/* loaded from: classes.dex */
public final class H implements O {
    public final AbstractC1206s a;
    public final Q b;
    public final C1201m c;

    public H(Q q, C1201m c1201m, AbstractC1206s abstractC1206s) {
        this.b = q;
        c1201m.getClass();
        this.c = c1201m;
        this.a = abstractC1206s;
    }

    @Override // androidx.glance.appwidget.protobuf.O
    public final void a(Object obj, Object obj2) {
        P.k(this.b, obj, obj2);
    }

    @Override // androidx.glance.appwidget.protobuf.O
    public final void b(Object obj) {
        ((T) this.b).getClass();
        S s = ((AbstractC1206s) obj).unknownFields;
        if (s.e) {
            s.e = false;
        }
        this.c.getClass();
        android.support.v4.media.session.a.A(obj);
        throw null;
    }

    @Override // androidx.glance.appwidget.protobuf.O
    public final boolean c(Object obj) {
        this.c.getClass();
        android.support.v4.media.session.a.A(obj);
        throw null;
    }

    @Override // androidx.glance.appwidget.protobuf.O
    public final AbstractC1206s d() {
        AbstractC1206s abstractC1206s = this.a;
        return abstractC1206s != null ? abstractC1206s.h() : ((AbstractC1205q) abstractC1206s.b(5)).c();
    }

    @Override // androidx.glance.appwidget.protobuf.O
    public final int e(AbstractC1206s abstractC1206s) {
        ((T) this.b).getClass();
        S s = abstractC1206s.unknownFields;
        int i = s.d;
        if (i != -1) {
            return i;
        }
        int iH = 0;
        for (int i2 = 0; i2 < s.a; i2++) {
            int i3 = s.b[i2] >>> 3;
            iH += C1198j.h(3, (C1194f) s.c[i2]) + C1198j.k(i3) + C1198j.j(2) + (C1198j.j(1) * 2);
        }
        s.d = iH;
        return iH;
    }

    @Override // androidx.glance.appwidget.protobuf.O
    public final void f(Object obj, C1197i c1197i, C1200l c1200l) {
        this.b.a(obj);
        this.c.getClass();
        obj.getClass();
        throw new ClassCastException();
    }

    @Override // androidx.glance.appwidget.protobuf.O
    public final int g(AbstractC1206s abstractC1206s) {
        ((T) this.b).getClass();
        return abstractC1206s.unknownFields.hashCode();
    }

    @Override // androidx.glance.appwidget.protobuf.O
    public final void h(Object obj, A a) {
        this.c.getClass();
        android.support.v4.media.session.a.A(obj);
        throw null;
    }

    @Override // androidx.glance.appwidget.protobuf.O
    public final boolean i(AbstractC1206s abstractC1206s, AbstractC1206s abstractC1206s2) {
        T t = (T) this.b;
        t.getClass();
        S s = abstractC1206s.unknownFields;
        t.getClass();
        return s.equals(abstractC1206s2.unknownFields);
    }
}
