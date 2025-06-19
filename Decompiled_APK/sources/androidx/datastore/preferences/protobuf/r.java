package androidx.datastore.preferences.protobuf;

/* loaded from: classes.dex */
public final class r implements I {
    public static final r b = new r(0);
    public final /* synthetic */ int a;

    public /* synthetic */ r(int i) {
        this.a = i;
    }

    @Override // androidx.datastore.preferences.protobuf.I
    public final T a(Class cls) {
        switch (this.a) {
            case 0:
                if (!AbstractC1113u.class.isAssignableFrom(cls)) {
                    throw new IllegalArgumentException("Unsupported message type: ".concat(cls.getName()));
                }
                try {
                    return (T) AbstractC1113u.d(cls.asSubclass(AbstractC1113u.class)).c(3);
                } catch (Exception e) {
                    throw new RuntimeException("Unable to get message info for ".concat(cls.getName()), e);
                }
            default:
                throw new IllegalStateException("This should never be called.");
        }
    }

    @Override // androidx.datastore.preferences.protobuf.I
    public final boolean b(Class cls) {
        switch (this.a) {
            case 0:
                return AbstractC1113u.class.isAssignableFrom(cls);
            default:
                return false;
        }
    }
}
