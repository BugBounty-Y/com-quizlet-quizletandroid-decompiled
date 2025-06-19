package androidx.lifecycle;

import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.lifecycle.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1246g implements H {
    public final /* synthetic */ int a = 1;
    public final Object b;

    public C1246g(InterfaceC1260v[] generatedAdapters) {
        Intrinsics.checkNotNullParameter(generatedAdapters, "generatedAdapters");
        this.b = generatedAdapters;
    }

    @Override // androidx.lifecycle.H
    public final void d(J source, A event) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(event, "event");
                new HashMap();
                InterfaceC1260v[] interfaceC1260vArr = (InterfaceC1260v[]) this.b;
                if (interfaceC1260vArr.length > 0) {
                    InterfaceC1260v interfaceC1260v = interfaceC1260vArr[0];
                    throw null;
                }
                if (interfaceC1260vArr.length <= 0) {
                    return;
                }
                InterfaceC1260v interfaceC1260v2 = interfaceC1260vArr[0];
                throw null;
            default:
                Intrinsics.checkNotNullParameter(source, "source");
                Intrinsics.checkNotNullParameter(event, "event");
                if (event == A.ON_CREATE) {
                    source.getLifecycle().b(this);
                    ((q0) this.b).b();
                    return;
                } else {
                    throw new IllegalStateException(("Next event must be ON_CREATE, it was " + event).toString());
                }
        }
    }

    public C1246g(q0 provider) {
        Intrinsics.checkNotNullParameter(provider, "provider");
        this.b = provider;
    }
}
