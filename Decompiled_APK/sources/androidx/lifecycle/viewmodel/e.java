package androidx.lifecycle.viewmodel;

import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e extends c {
    public e(c initialExtras) {
        Intrinsics.checkNotNullParameter(initialExtras, "initialExtras");
        LinkedHashMap initialExtras2 = initialExtras.a;
        Intrinsics.checkNotNullParameter(initialExtras2, "initialExtras");
        this.a.putAll(initialExtras2);
    }

    @Override // androidx.lifecycle.viewmodel.c
    public final Object a(b key) {
        Intrinsics.checkNotNullParameter(key, "key");
        return this.a.get(key);
    }

    public final void b(b key, Object obj) {
        Intrinsics.checkNotNullParameter(key, "key");
        this.a.put(key, obj);
    }

    public /* synthetic */ e(int i) {
        this(a.b);
    }
}
