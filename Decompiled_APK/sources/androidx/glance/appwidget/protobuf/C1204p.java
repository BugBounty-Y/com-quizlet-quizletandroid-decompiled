package androidx.glance.appwidget.protobuf;

/* renamed from: androidx.glance.appwidget.protobuf.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1204p implements E {
    public static final C1204p b = new C1204p(0);
    public final /* synthetic */ int a;

    public /* synthetic */ C1204p(int i) {
        this.a = i;
    }

    @Override // androidx.glance.appwidget.protobuf.E
    public final N a(Class cls) {
        switch (this.a) {
            case 0:
                if (!AbstractC1206s.class.isAssignableFrom(cls)) {
                    throw new IllegalArgumentException("Unsupported message type: ".concat(cls.getName()));
                }
                try {
                    return (N) AbstractC1206s.c(cls.asSubclass(AbstractC1206s.class)).b(3);
                } catch (Exception e) {
                    throw new RuntimeException("Unable to get message info for ".concat(cls.getName()), e);
                }
            default:
                throw new IllegalStateException("This should never be called.");
        }
    }

    @Override // androidx.glance.appwidget.protobuf.E
    public final boolean b(Class cls) {
        switch (this.a) {
            case 0:
                return AbstractC1206s.class.isAssignableFrom(cls);
            default:
                return false;
        }
    }
}
