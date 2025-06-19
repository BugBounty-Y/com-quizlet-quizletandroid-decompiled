package androidx.datastore.preferences.protobuf;

/* loaded from: classes.dex */
public final class L implements U {
    public final AbstractC1113u a;
    public final Z b;
    public final C1107n c;

    public L(Z z, C1107n c1107n, AbstractC1113u abstractC1113u) {
        this.b = z;
        c1107n.getClass();
        this.c = c1107n;
        this.a = abstractC1113u;
    }

    @Override // androidx.datastore.preferences.protobuf.U
    public final void a(Object obj, Object obj2) {
        V.k(this.b, obj, obj2);
    }

    @Override // androidx.datastore.preferences.protobuf.U
    public final void b(Object obj) {
        ((b0) this.b).getClass();
        a0 a0Var = ((AbstractC1113u) obj).unknownFields;
        if (a0Var.e) {
            a0Var.e = false;
        }
        this.c.getClass();
        android.support.v4.media.session.a.A(obj);
        throw null;
    }

    @Override // androidx.datastore.preferences.protobuf.U
    public final boolean c(Object obj) {
        this.c.getClass();
        android.support.v4.media.session.a.A(obj);
        throw null;
    }

    @Override // androidx.datastore.preferences.protobuf.U
    public final AbstractC1113u d() {
        AbstractC1113u abstractC1113u = this.a;
        return abstractC1113u != null ? abstractC1113u.i() : ((AbstractC1111s) abstractC1113u.c(5)).c();
    }

    @Override // androidx.datastore.preferences.protobuf.U
    public final void e(Object obj, C c) {
        this.c.getClass();
        android.support.v4.media.session.a.A(obj);
        throw null;
    }

    @Override // androidx.datastore.preferences.protobuf.U
    public final int f(AbstractC1113u abstractC1113u) {
        ((b0) this.b).getClass();
        a0 a0Var = abstractC1113u.unknownFields;
        int i = a0Var.d;
        if (i != -1) {
            return i;
        }
        int iH = 0;
        for (int i2 = 0; i2 < a0Var.a; i2++) {
            int i3 = a0Var.b[i2] >>> 3;
            iH += C1104k.h(3, (C1100g) a0Var.c[i2]) + C1104k.k(i3) + C1104k.j(2) + (C1104k.j(1) * 2);
        }
        a0Var.d = iH;
        return iH;
    }

    @Override // androidx.datastore.preferences.protobuf.U
    public final int g(AbstractC1113u abstractC1113u) {
        ((b0) this.b).getClass();
        return abstractC1113u.unknownFields.hashCode();
    }

    @Override // androidx.datastore.preferences.protobuf.U
    public final boolean h(AbstractC1113u abstractC1113u, AbstractC1113u abstractC1113u2) {
        b0 b0Var = (b0) this.b;
        b0Var.getClass();
        a0 a0Var = abstractC1113u.unknownFields;
        b0Var.getClass();
        return a0Var.equals(abstractC1113u2.unknownFields);
    }

    @Override // androidx.datastore.preferences.protobuf.U
    public final void i(Object obj, C1103j c1103j, C1106m c1106m) {
        this.b.a(obj);
        this.c.getClass();
        obj.getClass();
        throw new ClassCastException();
    }
}
