package androidx.compose.foundation.lazy.layout;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.ui.layout.AbstractC0885f;
import kotlin.NoWhenBranchMatchedException;

/* renamed from: androidx.compose.foundation.lazy.layout.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0445q implements androidx.compose.ui.modifier.f {
    public static final C0443o f = new C0443o();
    public final r b;
    public final com.airbnb.lottie.network.d c;
    public final androidx.compose.ui.unit.k d;
    public final EnumC0320d0 e;

    public C0445q(r rVar, com.airbnb.lottie.network.d dVar, androidx.compose.ui.unit.k kVar, EnumC0320d0 enumC0320d0) {
        this.b = rVar;
        this.c = dVar;
        this.d = kVar;
        this.e = enumC0320d0;
    }

    @Override // androidx.compose.ui.modifier.f
    public final androidx.compose.ui.modifier.h getKey() {
        return AbstractC0885f.a;
    }

    @Override // androidx.compose.ui.modifier.f
    public final Object getValue() {
        return this;
    }

    public final boolean l(C0442n c0442n, int i) {
        EnumC0320d0 enumC0320d0 = this.e;
        if (i == 5 || i == 6) {
            if (enumC0320d0 == EnumC0320d0.b) {
                return false;
            }
        } else if (i == 3 || i == 4) {
            if (enumC0320d0 == EnumC0320d0.a) {
                return false;
            }
        } else if (i != 1 && i != 2) {
            throw new IllegalStateException("Lazy list does not support beyond bounds layout for the specified direction");
        }
        if (n(i)) {
            if (c0442n.b >= this.b.d() - 1) {
                return false;
            }
        } else if (c0442n.a <= 0) {
            return false;
        }
        return true;
    }

    public final boolean n(int i) {
        if (i == 1) {
            return false;
        }
        if (i != 2) {
            if (i != 5) {
                if (i != 6) {
                    androidx.compose.ui.unit.k kVar = this.d;
                    if (i == 3) {
                        int iOrdinal = kVar.ordinal();
                        if (iOrdinal != 0) {
                            if (iOrdinal != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                        }
                    } else {
                        if (i != 4) {
                            throw new IllegalStateException("Lazy list does not support beyond bounds layout for the specified direction");
                        }
                        int iOrdinal2 = kVar.ordinal();
                        if (iOrdinal2 != 0) {
                            if (iOrdinal2 != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                        }
                    }
                }
            }
            return false;
        }
        return true;
    }
}
