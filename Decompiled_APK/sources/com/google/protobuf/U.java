package com.google.protobuf;

/* loaded from: classes2.dex */
public final class U implements InterfaceC4009c0 {
    public final AbstractC4004a a;
    public final j0 b;
    public final C4021o c;

    public U(j0 j0Var, C4021o c4021o, AbstractC4004a abstractC4004a) {
        this.b = j0Var;
        c4021o.getClass();
        this.c = c4021o;
        this.a = abstractC4004a;
    }

    @Override // com.google.protobuf.InterfaceC4009c0
    public final void a(Object obj, Object obj2) {
        d0.k(this.b, obj, obj2);
    }

    @Override // com.google.protobuf.InterfaceC4009c0
    public final void b(Object obj) {
        ((l0) this.b).getClass();
        k0 k0Var = ((AbstractC4027v) obj).unknownFields;
        if (k0Var.e) {
            k0Var.e = false;
        }
        this.c.getClass();
        android.support.v4.media.session.a.A(obj);
        throw null;
    }

    @Override // com.google.protobuf.InterfaceC4009c0
    public final boolean c(Object obj) {
        this.c.getClass();
        android.support.v4.media.session.a.A(obj);
        throw null;
    }

    @Override // com.google.protobuf.InterfaceC4009c0
    public final AbstractC4027v d() {
        AbstractC4004a abstractC4004a = this.a;
        return abstractC4004a instanceof AbstractC4027v ? ((AbstractC4027v) abstractC4004a).s() : ((AbstractC4025t) ((AbstractC4027v) abstractC4004a).l(5)).i();
    }

    @Override // com.google.protobuf.InterfaceC4009c0
    public final void e(Object obj, K k) {
        this.c.getClass();
        android.support.v4.media.session.a.A(obj);
        throw null;
    }

    @Override // com.google.protobuf.InterfaceC4009c0
    public final void f(Object obj, C4015i c4015i, C4020n c4020n) {
        this.b.a(obj);
        this.c.getClass();
        obj.getClass();
        throw new ClassCastException();
    }

    @Override // com.google.protobuf.InterfaceC4009c0
    public final int g(AbstractC4027v abstractC4027v) {
        ((l0) this.b).getClass();
        return abstractC4027v.unknownFields.hashCode();
    }

    @Override // com.google.protobuf.InterfaceC4009c0
    public final int h(AbstractC4027v abstractC4027v) {
        ((l0) this.b).getClass();
        k0 k0Var = abstractC4027v.unknownFields;
        int i = k0Var.d;
        if (i != -1) {
            return i;
        }
        int iG = 0;
        for (int i2 = 0; i2 < k0Var.a; i2++) {
            int i3 = k0Var.b[i2] >>> 3;
            iG += AbstractC4018l.g(3, (C4012f) k0Var.c[i2]) + AbstractC4018l.k(i3) + AbstractC4018l.j(2) + (AbstractC4018l.j(1) * 2);
        }
        k0Var.d = iG;
        return iG;
    }

    @Override // com.google.protobuf.InterfaceC4009c0
    public final boolean i(AbstractC4027v abstractC4027v, AbstractC4027v abstractC4027v2) {
        l0 l0Var = (l0) this.b;
        l0Var.getClass();
        k0 k0Var = abstractC4027v.unknownFields;
        l0Var.getClass();
        return k0Var.equals(abstractC4027v2.unknownFields);
    }
}
