package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class U1 implements InterfaceC3025m2 {
    public static final U1 b = new U1(0);
    public final /* synthetic */ int a;

    public /* synthetic */ U1(int i) {
        this.a = i;
    }

    public static final C3015k2 a(Object obj, Object obj2) {
        C3015k2 c3015k2 = (C3015k2) obj;
        C3015k2 c3015k22 = (C3015k2) obj2;
        if (!c3015k22.isEmpty()) {
            if (!c3015k2.a) {
                if (c3015k2.isEmpty()) {
                    c3015k2 = new C3015k2();
                } else {
                    C3015k2 c3015k23 = new C3015k2(c3015k2);
                    c3015k23.a = true;
                    c3015k2 = c3015k23;
                }
            }
            c3015k2.d();
            if (!c3015k22.isEmpty()) {
                c3015k2.putAll(c3015k22);
            }
        }
        return c3015k2;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3025m2
    public C3064u2 c(Class cls) {
        switch (this.a) {
            case 0:
                if (!W1.class.isAssignableFrom(cls)) {
                    throw new IllegalArgumentException("Unsupported message type: ".concat(cls.getName()));
                }
                try {
                    return (C3064u2) W1.g(cls.asSubclass(W1.class)).m(3);
                } catch (Exception e) {
                    throw new RuntimeException("Unable to get message info for ".concat(cls.getName()), e);
                }
            default:
                throw new IllegalStateException("This should never be called.");
        }
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3025m2
    public boolean d(Class cls) {
        switch (this.a) {
            case 0:
                return W1.class.isAssignableFrom(cls);
            default:
                return false;
        }
    }
}
