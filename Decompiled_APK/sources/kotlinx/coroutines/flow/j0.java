package kotlinx.coroutines.flow;

import androidx.datastore.core.C1087t;

/* loaded from: classes3.dex */
public final class j0 implements i0 {
    public final /* synthetic */ int a;

    @Override // kotlinx.coroutines.flow.i0
    public final InterfaceC4992i a(kotlinx.coroutines.flow.internal.H h) {
        switch (this.a) {
            case 0:
                return new C1087t(g0.a, 10);
            default:
                return new C1087t(new m0(h, null));
        }
    }

    public final String toString() {
        switch (this.a) {
            case 0:
                return "SharingStarted.Eagerly";
            default:
                return "SharingStarted.Lazily";
        }
    }
}
