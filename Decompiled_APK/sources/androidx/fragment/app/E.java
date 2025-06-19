package androidx.fragment.app;

import android.os.Bundle;

/* loaded from: classes.dex */
public final /* synthetic */ class E implements androidx.savedstate.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ E(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.savedstate.c
    public final Bundle a() {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                int i = I.a;
                I i2 = (I) obj;
                i2.markFragmentsCreated();
                i2.mFragmentLifecycleRegistry.e(androidx.lifecycle.A.ON_STOP);
                return new Bundle();
            default:
                return ((AbstractC1136h0) obj).c0();
        }
    }
}
