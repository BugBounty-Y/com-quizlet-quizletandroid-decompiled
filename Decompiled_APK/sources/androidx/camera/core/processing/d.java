package androidx.camera.core.processing;

import androidx.collection.V;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d implements androidx.core.util.a {
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ d() {
        this.a = 0;
    }

    @Override // androidx.core.util.a
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                Intrinsics.e((androidx.core.util.a) this.b, "Listener is not set.");
                ((androidx.core.util.a) this.b).accept(obj);
                return;
            case 1:
                androidx.core.provider.f fVar = (androidx.core.provider.f) obj;
                if (fVar == null) {
                    fVar = new androidx.core.provider.f(-3);
                }
                ((androidx.work.impl.model.c) this.b).w(fVar);
                return;
            default:
                androidx.core.provider.f fVar2 = (androidx.core.provider.f) obj;
                synchronized (androidx.core.provider.g.c) {
                    try {
                        V v = androidx.core.provider.g.d;
                        ArrayList arrayList = (ArrayList) v.get((String) this.b);
                        if (arrayList == null) {
                            return;
                        }
                        v.remove((String) this.b);
                        for (int i = 0; i < arrayList.size(); i++) {
                            ((androidx.core.util.a) arrayList.get(i)).accept(fVar2);
                        }
                        return;
                    } finally {
                    }
                }
        }
    }

    public /* synthetic */ d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }
}
