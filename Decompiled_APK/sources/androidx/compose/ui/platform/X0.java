package androidx.compose.ui.platform;

import androidx.navigation.C1291m;
import java.util.Iterator;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class X0 implements androidx.lifecycle.H {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ X0(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.lifecycle.H
    public final void d(androidx.lifecycle.J j, androidx.lifecycle.A event) {
        switch (this.a) {
            case 0:
                if (event == androidx.lifecycle.A.ON_DESTROY) {
                    ((AbstractC0930a) this.b).disposeComposition();
                    break;
                }
                break;
            case 1:
                Intrinsics.checkNotNullParameter(j, "<unused var>");
                Intrinsics.checkNotNullParameter(event, "event");
                androidx.lifecycle.B bA = event.a();
                androidx.navigation.internal.j jVar = (androidx.navigation.internal.j) this.b;
                jVar.q = bA;
                if (jVar.c != null) {
                    Iterator it2 = CollectionsKt.y0(jVar.f).iterator();
                    while (it2.hasNext()) {
                        C1291m c1291m = (C1291m) it2.next();
                        c1291m.getClass();
                        Intrinsics.checkNotNullParameter(event, "event");
                        androidx.navigation.internal.c cVar = c1291m.h;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(event, "event");
                        cVar.d = event.a();
                        cVar.b();
                    }
                    break;
                }
                break;
            case 2:
                Intrinsics.checkNotNullParameter(j, "<unused var>");
                Intrinsics.checkNotNullParameter(event, "event");
                androidx.lifecycle.A a = androidx.lifecycle.A.ON_START;
                C0978y0 c0978y0 = (C0978y0) this.b;
                if (event != a) {
                    if (event == androidx.lifecycle.A.ON_STOP) {
                        c0978y0.c = false;
                        break;
                    }
                } else {
                    c0978y0.c = true;
                    break;
                }
                break;
            default:
                com.onetrust.otpublishers.headless.UI.TVUI.fragments.n nVar = (com.onetrust.otpublishers.headless.UI.TVUI.fragments.n) this.b;
                nVar.getClass();
                if (event.compareTo(androidx.lifecycle.A.ON_RESUME) == 0) {
                    nVar.r.clearFocus();
                    nVar.q.clearFocus();
                    nVar.p.clearFocus();
                    break;
                }
                break;
        }
    }
}
