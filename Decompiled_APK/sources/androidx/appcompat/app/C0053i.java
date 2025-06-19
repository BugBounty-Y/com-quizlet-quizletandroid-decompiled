package androidx.appcompat.app;

import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import java.util.Arrays;
import java.util.LinkedHashSet;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.appcompat.app.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0053i implements androidx.savedstate.c {
    public final /* synthetic */ int a = 0;
    public final Object b;

    public C0053i(androidx.savedstate.d registry) {
        Intrinsics.checkNotNullParameter(registry, "registry");
        this.b = new LinkedHashSet();
        registry.c("androidx.savedstate.Restarter", this);
    }

    @Override // androidx.savedstate.c
    public final Bundle a() {
        switch (this.a) {
            case 0:
                Bundle bundle = new Bundle();
                ((AbstractActivityC0055k) this.b).q().getClass();
                return bundle;
            default:
                V.c();
                Bundle source = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
                Intrinsics.checkNotNullParameter(source, "source");
                AbstractC3343g2.j(source, "classes_to_restore", CollectionsKt.w0((LinkedHashSet) this.b));
                return source;
        }
    }

    public C0053i(AbstractActivityC0055k abstractActivityC0055k) {
        this.b = abstractActivityC0055k;
    }
}
