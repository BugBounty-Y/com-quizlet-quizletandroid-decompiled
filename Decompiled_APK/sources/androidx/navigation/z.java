package androidx.navigation;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Parcelable;
import com.google.android.gms.internal.mlkit_vision_camera.H1;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.C4927s;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class z {
    public final Context a;
    public final androidx.navigation.internal.d b;
    public final Intent c;
    public final D d;
    public final ArrayList e;

    public z(@NotNull Context context) {
        Intent launchIntentForPackage;
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
        this.b = new androidx.navigation.internal.d(context);
        kotlin.sequences.f fVarI = kotlin.sequences.q.i(kotlin.sequences.n.c(new C1265a(5), context), new C1265a(6));
        Intrinsics.checkNotNullParameter(fVarI, "<this>");
        kotlin.sequences.e eVar = (kotlin.sequences.e) fVarI.iterator();
        Activity activity = (Activity) (!eVar.hasNext() ? null : eVar.next());
        if (activity != null) {
            launchIntentForPackage = new Intent(context, activity.getClass());
        } else {
            launchIntentForPackage = context.getPackageManager().getLaunchIntentForPackage(context.getPackageName());
            if (launchIntentForPackage == null) {
                launchIntentForPackage = new Intent();
            }
        }
        launchIntentForPackage.addFlags(268468224);
        this.c = launchIntentForPackage;
        this.e = new ArrayList();
    }

    public final androidx.core.app.W a() {
        D d = this.d;
        if (d == null) {
            throw new IllegalStateException("You must call setGraph() before constructing the deep link");
        }
        ArrayList arrayList = this.e;
        if (arrayList.isEmpty()) {
            throw new IllegalStateException("You must call setDestination() or addDestination() before constructing the deep link");
        }
        ArrayList arrayList2 = new ArrayList();
        ArrayList<? extends Parcelable> arrayList3 = new ArrayList<>();
        Iterator it2 = arrayList.iterator();
        B b = null;
        while (true) {
            int i = 0;
            if (!it2.hasNext()) {
                int[] iArrV0 = CollectionsKt.v0(arrayList2);
                Intent intent = this.c;
                intent.putExtra("android-support-nav:controller:deepLinkIds", iArrV0);
                intent.putParcelableArrayListExtra("android-support-nav:controller:deepLinkArgs", arrayList3);
                androidx.core.app.W w = new androidx.core.app.W(this.a);
                w.a(new Intent(intent));
                Intrinsics.checkNotNullExpressionValue(w, "addNextIntentWithParentStack(...)");
                ArrayList arrayList4 = w.a;
                int size = arrayList4.size();
                while (i < size) {
                    Intent intent2 = (Intent) arrayList4.get(i);
                    if (intent2 != null) {
                        intent2.putExtra("android-support-nav:controller:deepLinkIntent", intent);
                    }
                    i++;
                }
                return w;
            }
            C1302y c1302y = (C1302y) it2.next();
            int i2 = c1302y.a;
            B b2 = b(i2);
            if (b2 == null) {
                int i3 = B.e;
                throw new IllegalArgumentException("Navigation destination " + H1.a(this.b, i2) + " cannot be found in the navigation graph " + d);
            }
            int[] iArrE = b2.e(b);
            int length = iArrE.length;
            while (i < length) {
                arrayList2.add(Integer.valueOf(iArrE[i]));
                arrayList3.add(c1302y.b);
                i++;
            }
            b = b2;
        }
    }

    public final B b(int i) {
        C4927s c4927s = new C4927s();
        D d = this.d;
        Intrinsics.d(d);
        c4927s.addLast(d);
        while (!c4927s.isEmpty()) {
            B b = (B) c4927s.removeFirst();
            if (b.b.c == i) {
                return b;
            }
            if (b instanceof D) {
                Iterator it2 = ((D) b).iterator();
                while (true) {
                    androidx.navigation.internal.n nVar = (androidx.navigation.internal.n) it2;
                    if (nVar.hasNext()) {
                        c4927s.addLast((B) nVar.next());
                    }
                }
            }
        }
        return null;
    }

    public final void c() {
        Iterator it2 = this.e.iterator();
        while (it2.hasNext()) {
            int i = ((C1302y) it2.next()).a;
            if (b(i) == null) {
                int i2 = B.e;
                StringBuilder sbY = android.support.v4.media.session.a.y("Navigation destination ", H1.a(this.b, i), " cannot be found in the navigation graph ");
                sbY.append(this.d);
                throw new IllegalArgumentException(sbY.toString());
            }
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public z(H navController) {
        this(navController.a);
        Intrinsics.checkNotNullParameter(navController, "navController");
        this.d = navController.b.h();
    }
}
