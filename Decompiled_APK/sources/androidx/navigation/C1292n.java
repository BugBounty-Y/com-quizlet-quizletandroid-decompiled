package androidx.navigation;

import android.content.Context;
import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import java.util.Arrays;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.navigation.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1292n {
    public final com.google.android.gms.cloudmessaging.k a;

    public C1292n(C1291m entry) {
        Intrinsics.checkNotNullParameter(entry, "entry");
        this.a = new com.google.android.gms.cloudmessaging.k(entry, entry.b.b.c);
    }

    public final C1291m a(androidx.navigation.internal.d context, B destination, androidx.lifecycle.B hostLifecycleState, C1296s c1296s) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(destination, "destination");
        Intrinsics.checkNotNullParameter(hostLifecycleState, "hostLifecycleState");
        com.google.android.gms.cloudmessaging.k kVar = this.a;
        Bundle args = (Bundle) kVar.d;
        if (args != null) {
            Intrinsics.checkNotNullParameter(args, "args");
            Intrinsics.checkNotNullParameter(context, "context");
            Context context2 = context.a;
            args.setClassLoader(context2 != null ? context2.getClassLoader() : null);
        } else {
            args = null;
        }
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(destination, "destination");
        Intrinsics.checkNotNullParameter(hostLifecycleState, "hostLifecycleState");
        Intrinsics.checkNotNullParameter(destination, "destination");
        Intrinsics.checkNotNullParameter(hostLifecycleState, "hostLifecycleState");
        String id = (String) kVar.c;
        Intrinsics.checkNotNullParameter(id, "id");
        return new C1291m(context, destination, args, hostLifecycleState, c1296s, id, (Bundle) kVar.e);
    }

    public final Bundle b() {
        com.google.android.gms.cloudmessaging.k kVar = this.a;
        kVar.getClass();
        kotlin.collections.V.c();
        Bundle source = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
        Intrinsics.checkNotNullParameter(source, "source");
        AbstractC3343g2.h("nav-entry-state:id", (String) kVar.c, source);
        Intrinsics.checkNotNullParameter("nav-entry-state:destination-id", "key");
        source.putInt("nav-entry-state:destination-id", kVar.b);
        Bundle source2 = (Bundle) kVar.d;
        if (source2 == null) {
            kotlin.collections.V.c();
            source2 = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
            Intrinsics.checkNotNullParameter(source2, "source");
        }
        AbstractC3343g2.g(source, "nav-entry-state:args", source2);
        AbstractC3343g2.g(source, "nav-entry-state:saved-state", (Bundle) kVar.e);
        return source;
    }

    public C1292n(Bundle state) {
        Intrinsics.checkNotNullParameter(state, "state");
        state.setClassLoader(C1292n.class.getClassLoader());
        this.a = new com.google.android.gms.cloudmessaging.k(state);
    }
}
