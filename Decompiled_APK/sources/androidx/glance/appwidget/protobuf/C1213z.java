package androidx.glance.appwidget.protobuf;

/* renamed from: androidx.glance.appwidget.protobuf.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1213z implements E {
    public E[] a;

    @Override // androidx.glance.appwidget.protobuf.E
    public final N a(Class cls) {
        for (E e : this.a) {
            if (e.b(cls)) {
                return e.a(cls);
            }
        }
        throw new UnsupportedOperationException("No factory is available for message type: ".concat(cls.getName()));
    }

    @Override // androidx.glance.appwidget.protobuf.E
    public final boolean b(Class cls) {
        for (E e : this.a) {
            if (e.b(cls)) {
                return true;
            }
        }
        return false;
    }
}
