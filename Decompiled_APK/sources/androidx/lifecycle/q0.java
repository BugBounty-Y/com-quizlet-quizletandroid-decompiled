package androidx.lifecycle;

import android.os.Bundle;
import androidx.activity.C0034f;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import java.util.Arrays;
import java.util.Map;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class q0 implements androidx.savedstate.c {
    public final androidx.savedstate.d a;
    public boolean b;
    public Bundle c;
    public final kotlin.u d;

    public q0(androidx.savedstate.d savedStateRegistry, C0 viewModelStoreOwner) {
        Intrinsics.checkNotNullParameter(savedStateRegistry, "savedStateRegistry");
        Intrinsics.checkNotNullParameter(viewModelStoreOwner, "viewModelStoreOwner");
        this.a = savedStateRegistry;
        this.d = kotlin.l.b(new C1247h(viewModelStoreOwner, 1));
    }

    @Override // androidx.savedstate.c
    public final Bundle a() {
        kotlin.collections.V.c();
        Bundle source = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
        Intrinsics.checkNotNullParameter(source, "source");
        Bundle from = this.c;
        if (from != null) {
            Intrinsics.checkNotNullParameter(from, "from");
            source.putAll(from);
        }
        for (Map.Entry entry : ((r0) this.d.getValue()).b.entrySet()) {
            String str = (String) entry.getKey();
            Bundle source2 = ((C0034f) ((m0) entry.getValue()).b.f).a();
            Intrinsics.checkNotNullParameter(source2, "source");
            if (!source2.isEmpty()) {
                AbstractC3343g2.g(source, str, source2);
            }
        }
        this.b = false;
        return source;
    }

    public final void b() {
        if (this.b) {
            return;
        }
        Bundle from = this.a.a("androidx.lifecycle.internal.SavedStateHandlesProvider");
        kotlin.collections.V.c();
        Bundle source = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
        Intrinsics.checkNotNullParameter(source, "source");
        Bundle from2 = this.c;
        if (from2 != null) {
            Intrinsics.checkNotNullParameter(from2, "from");
            source.putAll(from2);
        }
        if (from != null) {
            Intrinsics.checkNotNullParameter(from, "from");
            source.putAll(from);
        }
        this.c = source;
        this.b = true;
    }
}
