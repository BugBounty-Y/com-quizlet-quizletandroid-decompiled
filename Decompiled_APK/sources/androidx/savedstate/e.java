package androidx.savedstate;

import android.os.Bundle;
import androidx.compose.ui.platform.C0978y0;
import androidx.lifecycle.B;
import androidx.lifecycle.L;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e {
    public final C0978y0 a;
    public final d b;

    public e(C0978y0 c0978y0) {
        this.a = c0978y0;
        this.b = new d(c0978y0);
    }

    public final void a(Bundle source) {
        C0978y0 c0978y0 = this.a;
        if (!c0978y0.a) {
            c0978y0.d();
        }
        f fVar = (f) c0978y0.d;
        if (((L) fVar.getLifecycle()).d.a(B.d)) {
            throw new IllegalStateException(("performRestore cannot be called when owner is " + ((L) fVar.getLifecycle()).d).toString());
        }
        if (c0978y0.b) {
            throw new IllegalStateException("SavedStateRegistry was already restored.");
        }
        Bundle bundleH = null;
        if (source != null) {
            Intrinsics.checkNotNullParameter(source, "source");
            Intrinsics.checkNotNullParameter("androidx.lifecycle.BundlableSavedStateRegistry.key", "key");
            if (source.containsKey("androidx.lifecycle.BundlableSavedStateRegistry.key")) {
                bundleH = AbstractC3335e2.h(source, "androidx.lifecycle.BundlableSavedStateRegistry.key");
            }
        }
        c0978y0.h = bundleH;
        c0978y0.b = true;
    }

    public final void b(Bundle source) {
        Intrinsics.checkNotNullParameter(source, "outBundle");
        C0978y0 c0978y0 = this.a;
        Intrinsics.checkNotNullParameter(source, "outBundle");
        V.c();
        Bundle source2 = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
        Intrinsics.checkNotNullParameter(source2, "source");
        Bundle from = (Bundle) c0978y0.h;
        if (from != null) {
            Intrinsics.checkNotNullParameter(from, "from");
            source2.putAll(from);
        }
        synchronized (((u) c0978y0.f)) {
            try {
                for (Map.Entry entry : ((LinkedHashMap) c0978y0.g).entrySet()) {
                    AbstractC3343g2.g(source2, (String) entry.getKey(), ((c) entry.getValue()).a());
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
        Intrinsics.checkNotNullParameter(source2, "source");
        if (source2.isEmpty()) {
            return;
        }
        Intrinsics.checkNotNullParameter(source, "source");
        AbstractC3343g2.g(source, "androidx.lifecycle.BundlableSavedStateRegistry.key", source2);
    }
}
