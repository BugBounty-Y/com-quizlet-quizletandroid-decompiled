package androidx.datastore.preferences.protobuf;

/* loaded from: classes.dex */
public final class B implements I {
    public I[] a;

    @Override // androidx.datastore.preferences.protobuf.I
    public final T a(Class cls) {
        for (I i : this.a) {
            if (i.b(cls)) {
                return i.a(cls);
            }
        }
        throw new UnsupportedOperationException("No factory is available for message type: ".concat(cls.getName()));
    }

    @Override // androidx.datastore.preferences.protobuf.I
    public final boolean b(Class cls) {
        for (I i : this.a) {
            if (i.b(cls)) {
                return true;
            }
        }
        return false;
    }
}
