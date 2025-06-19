package org.koin.core.module;

import androidx.compose.ui.node.B;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3402v2;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import kotlin.collections.G;
import kotlin.jvm.internal.Intrinsics;
import org.koin.core.instance.b;

/* loaded from: classes3.dex */
public final class a {
    public final String a = B.f("toString(...)");
    public final HashSet b = new HashSet();
    public final HashMap c = new HashMap();
    public final HashSet d = new HashSet();
    public final ArrayList e = new ArrayList();

    public final void a(a... module) {
        Intrinsics.checkNotNullParameter(module, "module");
        G.v(this.e, module);
    }

    public final void b(b instanceFactory) {
        Intrinsics.checkNotNullParameter(instanceFactory, "instanceFactory");
        org.koin.core.definition.b bVar = instanceFactory.a;
        c(AbstractC3402v2.b(bVar.b, bVar.c, bVar.a), instanceFactory);
    }

    public final void c(String mapping, b factory) {
        Intrinsics.checkNotNullParameter(mapping, "mapping");
        Intrinsics.checkNotNullParameter(factory, "factory");
        this.c.put(mapping, factory);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return obj != null && a.class == obj.getClass() && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
