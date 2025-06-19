package androidx.navigation;

import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public class D extends B implements Iterable, kotlin.jvm.internal.markers.a {
    public static final /* synthetic */ int g = 0;
    public final androidx.camera.camera2.internal.concurrent.a f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(G navGraphNavigator) {
        super(navGraphNavigator);
        Intrinsics.checkNotNullParameter(navGraphNavigator, "navGraphNavigator");
        this.f = new androidx.camera.camera2.internal.concurrent.a(this);
    }

    @Override // androidx.navigation.B
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof D) || !super.equals(obj)) {
            return false;
        }
        androidx.camera.camera2.internal.concurrent.a aVar = this.f;
        int iG = ((androidx.collection.W) aVar.d).g();
        androidx.camera.camera2.internal.concurrent.a aVar2 = ((D) obj).f;
        if (iG != ((androidx.collection.W) aVar2.d).g() || aVar.b != aVar2.b) {
            return false;
        }
        androidx.collection.W w = (androidx.collection.W) aVar.d;
        Intrinsics.checkNotNullParameter(w, "<this>");
        Iterator it2 = kotlin.sequences.n.b(new androidx.collection.Y(w, 0)).iterator();
        while (it2.hasNext()) {
            B b = (B) it2.next();
            if (!b.equals(((androidx.collection.W) aVar2.d).d(b.b.c))) {
                return false;
            }
        }
        return true;
    }

    @Override // androidx.navigation.B
    public final int hashCode() {
        androidx.camera.camera2.internal.concurrent.a aVar = this.f;
        int iE = aVar.b;
        androidx.collection.W w = (androidx.collection.W) aVar.d;
        int iG = w.g();
        for (int i = 0; i < iG; i++) {
            iE = (((iE * 31) + w.e(i)) * 31) + ((B) w.h(i)).hashCode();
        }
        return iE;
    }

    @Override // androidx.navigation.B
    public final A i(com.quizlet.data.repository.set.f navDeepLinkRequest) {
        Intrinsics.checkNotNullParameter(navDeepLinkRequest, "navDeepLinkRequest");
        A aI = super.i(navDeepLinkRequest);
        androidx.camera.camera2.internal.concurrent.a aVar = this.f;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(navDeepLinkRequest, "navDeepLinkRequest");
        return aVar.G(aI, navDeepLinkRequest, false, (D) aVar.c);
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        androidx.camera.camera2.internal.concurrent.a aVar = this.f;
        aVar.getClass();
        return new androidx.navigation.internal.n(aVar);
    }

    public final B k(String str) {
        androidx.camera.camera2.internal.concurrent.a aVar = this.f;
        aVar.getClass();
        if (str == null || StringsKt.O(str)) {
            return null;
        }
        return aVar.t(str, true);
    }

    public final A m(com.quizlet.data.repository.set.f navDeepLinkRequest, B lastVisited) {
        Intrinsics.checkNotNullParameter(navDeepLinkRequest, "navDeepLinkRequest");
        Intrinsics.checkNotNullParameter(lastVisited, "lastVisited");
        return this.f.G(super.i(navDeepLinkRequest), navDeepLinkRequest, true, lastVisited);
    }

    public final A n(String route, boolean z, B lastVisited) {
        A aN;
        Intrinsics.checkNotNullParameter(route, "route");
        Intrinsics.checkNotNullParameter(lastVisited, "lastVisited");
        androidx.camera.camera2.internal.concurrent.a aVar = this.f;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(route, "route");
        Intrinsics.checkNotNullParameter(lastVisited, "lastVisited");
        D d = (D) aVar.c;
        d.getClass();
        Intrinsics.checkNotNullParameter(route, "route");
        A aI = d.b.i(route);
        ArrayList arrayList = new ArrayList();
        Iterator it2 = d.iterator();
        while (true) {
            androidx.navigation.internal.n nVar = (androidx.navigation.internal.n) it2;
            aN = null;
            if (!nVar.hasNext()) {
                break;
            }
            B b = (B) nVar.next();
            if (!Intrinsics.b(b, lastVisited)) {
                if (b instanceof D) {
                    aN = ((D) b).n(route, false, d);
                } else {
                    b.getClass();
                    Intrinsics.checkNotNullParameter(route, "route");
                    aN = b.b.i(route);
                }
            }
            if (aN != null) {
                arrayList.add(aN);
            }
        }
        A a = (A) CollectionsKt.W(arrayList);
        D d2 = d.c;
        if (d2 != null && z && !d2.equals(lastVisited)) {
            aN = d2.n(route, true, d);
        }
        A[] elements = {aI, a, aN};
        Intrinsics.checkNotNullParameter(elements, "elements");
        return (A) CollectionsKt.W(C4933y.z(elements));
    }

    @Override // androidx.navigation.B
    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString());
        androidx.camera.camera2.internal.concurrent.a aVar = this.f;
        B bK = k((String) aVar.f);
        if (bK == null) {
            bK = aVar.s(aVar.b);
        }
        sb.append(" startDestination=");
        if (bK == null) {
            String str = (String) aVar.f;
            if (str != null) {
                sb.append(str);
            } else {
                String str2 = (String) aVar.e;
                if (str2 != null) {
                    sb.append(str2);
                } else {
                    sb.append("0x" + Integer.toHexString(aVar.b));
                }
            }
        } else {
            sb.append("{");
            sb.append(bK.toString());
            sb.append("}");
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }
}
