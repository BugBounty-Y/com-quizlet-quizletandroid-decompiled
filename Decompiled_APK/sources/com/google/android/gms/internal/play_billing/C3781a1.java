package com.google.android.gms.internal.play_billing;

/* renamed from: com.google.android.gms.internal.play_billing.a1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3781a1 implements InterfaceC3826p1 {
    public static final C3781a1 b = new C3781a1(0);
    public final /* synthetic */ int a;

    public /* synthetic */ C3781a1(int i) {
        this.a = i;
    }

    public static final C3820n1 a(Object obj, Object obj2) {
        C3820n1 c3820n1 = (C3820n1) obj;
        C3820n1 c3820n12 = (C3820n1) obj2;
        if (!c3820n12.isEmpty()) {
            if (!c3820n1.a) {
                if (c3820n1.isEmpty()) {
                    c3820n1 = new C3820n1();
                } else {
                    C3820n1 c3820n13 = new C3820n1(c3820n1);
                    c3820n13.a = true;
                    c3820n1 = c3820n13;
                }
            }
            c3820n1.d();
            if (!c3820n12.isEmpty()) {
                c3820n1.putAll(c3820n12);
            }
        }
        return c3820n1;
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3826p1
    public C3849x1 c(Class cls) {
        switch (this.a) {
            case 0:
                if (!AbstractC3787c1.class.isAssignableFrom(cls)) {
                    throw new IllegalArgumentException("Unsupported message type: ".concat(cls.getName()));
                }
                try {
                    return (C3849x1) AbstractC3787c1.h(cls.asSubclass(AbstractC3787c1.class)).d(3);
                } catch (Exception e) {
                    throw new RuntimeException("Unable to get message info for ".concat(cls.getName()), e);
                }
            default:
                throw new IllegalStateException("This should never be called.");
        }
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3826p1
    public boolean d(Class cls) {
        switch (this.a) {
            case 0:
                return AbstractC3787c1.class.isAssignableFrom(cls);
            default:
                return false;
        }
    }
}
