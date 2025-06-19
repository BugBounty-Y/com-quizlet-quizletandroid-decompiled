package androidx.navigation;

import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.E1;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

@V("navigation")
@Metadata
/* loaded from: classes.dex */
public class G extends W {
    public final X c;

    public G(X navigatorProvider) {
        Intrinsics.checkNotNullParameter(navigatorProvider, "navigatorProvider");
        Intrinsics.checkNotNullParameter("navigation", "name");
        this.c = navigatorProvider;
    }

    @Override // androidx.navigation.W
    public final void d(List entries, K k) {
        B bT;
        Intrinsics.checkNotNullParameter(entries, "entries");
        Iterator it2 = entries.iterator();
        while (it2.hasNext()) {
            C1291m c1291m = (C1291m) it2.next();
            B b = c1291m.b;
            Intrinsics.e(b, "null cannot be cast to non-null type androidx.navigation.NavGraph");
            D d = (D) b;
            kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
            j.a = c1291m.h.a();
            androidx.camera.camera2.internal.concurrent.a aVar = d.f;
            int i = aVar.b;
            String route = (String) aVar.f;
            if (i == 0 && route == null) {
                StringBuilder sb = new StringBuilder("no start destination defined via app:startDestination for ");
                androidx.navigation.internal.m mVar = d.b;
                mVar.getClass();
                String superName = String.valueOf(mVar.c);
                Intrinsics.checkNotNullParameter(superName, "superName");
                if (((D) aVar.c).b.c == 0) {
                    superName = "the root navigation";
                }
                sb.append(superName);
                throw new IllegalStateException(sb.toString().toString());
            }
            if (route != null) {
                Intrinsics.checkNotNullParameter(route, "route");
                bT = aVar.t(route, false);
            } else {
                bT = (B) ((androidx.collection.W) aVar.d).d(i);
            }
            if (bT == null) {
                if (((String) aVar.e) == null) {
                    String strValueOf = (String) aVar.f;
                    if (strValueOf == null) {
                        strValueOf = String.valueOf(aVar.b);
                    }
                    aVar.e = strValueOf;
                }
                String str = (String) aVar.e;
                Intrinsics.d(str);
                throw new IllegalArgumentException(android.support.v4.media.session.a.B("navigation destination ", str, " is not a direct child of this NavGraph"));
            }
            if (route != null) {
                androidx.navigation.internal.m mVar2 = bT.b;
                if (!route.equals((String) mVar2.f)) {
                    Intrinsics.checkNotNullParameter(route, "route");
                    A aI = mVar2.i(route);
                    Bundle from = aI != null ? aI.b : null;
                    if (from != null) {
                        Intrinsics.checkNotNullParameter(from, "source");
                        if (!from.isEmpty()) {
                            kotlin.collections.V.c();
                            Bundle source = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
                            Intrinsics.checkNotNullParameter(source, "source");
                            Intrinsics.checkNotNullParameter(from, "from");
                            source.putAll(from);
                            Bundle from2 = (Bundle) j.a;
                            if (from2 != null) {
                                Intrinsics.checkNotNullParameter(from2, "from");
                                source.putAll(from2);
                            }
                            j.a = source;
                        }
                    }
                }
                if (bT.h().isEmpty()) {
                    continue;
                } else {
                    ArrayList arrayListB = E1.b(bT.h(), new F(j, 0));
                    if (!arrayListB.isEmpty()) {
                        throw new IllegalArgumentException(("Cannot navigate to startDestination " + bT + ". Missing required arguments [" + arrayListB + ']').toString());
                    }
                }
            }
            this.c.c(bT.a).d(kotlin.collections.A.b(b().b(bT, bT.b((Bundle) j.a))), k);
        }
    }

    @Override // androidx.navigation.W
    /* renamed from: h, reason: merged with bridge method [inline-methods] */
    public D a() {
        return new D(this);
    }
}
