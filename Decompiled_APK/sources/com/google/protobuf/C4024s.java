package com.google.protobuf;

/* renamed from: com.google.protobuf.s, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4024s implements Q {
    public static final C4024s b = new C4024s(0);
    public final /* synthetic */ int a;

    public /* synthetic */ C4024s(int i) {
        this.a = i;
    }

    @Override // com.google.protobuf.Q
    public final C4007b0 a(Class cls) {
        switch (this.a) {
            case 0:
                if (!AbstractC4027v.class.isAssignableFrom(cls)) {
                    throw new IllegalArgumentException("Unsupported message type: ".concat(cls.getName()));
                }
                try {
                    return (C4007b0) AbstractC4027v.m(cls.asSubclass(AbstractC4027v.class)).l(3);
                } catch (Exception e) {
                    throw new RuntimeException("Unable to get message info for ".concat(cls.getName()), e);
                }
            default:
                throw new IllegalStateException("This should never be called.");
        }
    }

    @Override // com.google.protobuf.Q
    public final boolean b(Class cls) {
        switch (this.a) {
            case 0:
                return AbstractC4027v.class.isAssignableFrom(cls);
            default:
                return false;
        }
    }
}
