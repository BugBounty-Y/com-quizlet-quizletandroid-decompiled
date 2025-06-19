package androidx.navigation;

import com.google.android.gms.internal.mlkit_vision_camera.P1;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Home;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;

/* loaded from: classes.dex */
public final class E extends C {
    public final X g;
    public final String h;
    public final GlobalNavSuiteItem$Home i;
    public final ArrayList j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(X provider, String startDestination) {
        super(provider.b(G.class), (String) null);
        Intrinsics.checkNotNullParameter(provider, "provider");
        Intrinsics.checkNotNullParameter(startDestination, "startDestination");
        this.j = new ArrayList();
        this.g = provider;
        this.h = startDestination;
    }

    @Override // androidx.navigation.C
    /* renamed from: j, reason: merged with bridge method [inline-methods] */
    public final D a() {
        D d = (D) super.a();
        ArrayList nodes = this.j;
        Intrinsics.checkNotNullParameter(nodes, "nodes");
        androidx.camera.camera2.internal.concurrent.a aVar = d.f;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(nodes, "nodes");
        Iterator it2 = nodes.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            D d2 = (D) aVar.c;
            if (!zHasNext) {
                GlobalNavSuiteItem$Home startDestRoute = this.i;
                String startDestRoute2 = this.h;
                if (startDestRoute2 == null && startDestRoute == null) {
                    if (this.a != null) {
                        throw new IllegalStateException("You must set a start destination route");
                    }
                    throw new IllegalStateException("You must set a start destination id");
                }
                if (startDestRoute2 != null) {
                    Intrinsics.checkNotNullParameter(startDestRoute2, "startDestRoute");
                    Intrinsics.checkNotNullParameter(startDestRoute2, "startDestRoute");
                    aVar.O(startDestRoute2);
                    return d;
                }
                if (startDestRoute == null) {
                    if (d2.b.c == 0) {
                        throw new IllegalArgumentException(("Start destination 0 cannot use the same id as the graph " + d2).toString());
                    }
                    if (((String) aVar.f) != null) {
                        aVar.O(null);
                    }
                    aVar.b = 0;
                    aVar.e = null;
                    return d;
                }
                Intrinsics.checkNotNullParameter(startDestRoute, "startDestRoute");
                Intrinsics.checkNotNullParameter(startDestRoute, "startDestRoute");
                KSerializer serializer = P1.e(kotlin.jvm.internal.K.a(GlobalNavSuiteItem$Home.class));
                U parseRoute = new U(startDestRoute, 1);
                Intrinsics.checkNotNullParameter(serializer, "serializer");
                Intrinsics.checkNotNullParameter(parseRoute, "parseRoute");
                int iB = androidx.navigation.serialization.d.b(serializer);
                B bS = aVar.s(iB);
                if (bS != null) {
                    aVar.O((String) parseRoute.invoke(bS));
                    aVar.b = iB;
                    return d;
                }
                throw new IllegalStateException(("Cannot find startDestination " + serializer.getDescriptor().a() + " from NavGraph. Ensure the starting NavDestination was added with route from KClass.").toString());
            }
            B node = (B) it2.next();
            if (node != null) {
                Intrinsics.checkNotNullParameter(node, "node");
                androidx.navigation.internal.m mVar = node.b;
                int i = mVar.c;
                String str = (String) mVar.f;
                if (i == 0 && str == null) {
                    throw new IllegalArgumentException("Destinations must have an id or route. Call setId(), setRoute(), or include an android:id or app:route in your navigation XML.");
                }
                String str2 = (String) d2.b.f;
                if (str2 != null && Intrinsics.b(str, str2)) {
                    throw new IllegalArgumentException(("Destination " + node + " cannot have the same route as graph " + d2).toString());
                }
                if (i == d2.b.c) {
                    throw new IllegalArgumentException(("Destination " + node + " cannot have the same id as graph " + d2).toString());
                }
                androidx.collection.W w = (androidx.collection.W) aVar.d;
                B b = (B) w.d(i);
                if (b == node) {
                    continue;
                } else {
                    if (node.c != null) {
                        throw new IllegalStateException("Destination already has a parent set. Call NavGraph.remove() to remove the previous parent.");
                    }
                    if (b != null) {
                        b.c = null;
                    }
                    node.c = d2;
                    w.f(mVar.c, node);
                }
            }
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(X provider, GlobalNavSuiteItem$Home startDestination, kotlin.collections.L typeMap) {
        super(provider.b(G.class), (C4950i) null, typeMap);
        Intrinsics.checkNotNullParameter(provider, "provider");
        Intrinsics.checkNotNullParameter(startDestination, "startDestination");
        Intrinsics.checkNotNullParameter(typeMap, "typeMap");
        this.j = new ArrayList();
        this.g = provider;
        this.i = startDestination;
    }
}
