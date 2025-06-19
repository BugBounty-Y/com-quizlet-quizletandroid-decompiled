package androidx.navigation;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import com.google.android.gms.internal.mlkit_vision_camera.H1;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.google.android.gms.internal.mlkit_vision_camera.J1;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import kotlin.Pair;
import kotlin.collections.C4927s;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public class r {
    public final Context a;
    public final androidx.navigation.internal.j b;
    public final androidx.navigation.internal.d c;
    public final Activity d;
    public boolean e;
    public final androidx.activity.M f;
    public final boolean g;

    public r(@NotNull Context context) {
        Object next;
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
        this.b = new androidx.navigation.internal.j(this, new C1293o(this, 0));
        this.c = new androidx.navigation.internal.d(context);
        Iterator it2 = kotlin.sequences.n.c(new C1265a(1), context).iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            } else {
                next = it2.next();
                if (((Context) next) instanceof Activity) {
                    break;
                }
            }
        }
        this.d = (Activity) next;
        this.f = new androidx.activity.M(this);
        this.g = true;
        X x = this.b.s;
        x.a(new G(x));
        this.b.s.a(new C1267c(this.a));
        kotlin.l.b(new C1293o(this, 1));
    }

    public static void d(r rVar, String route) {
        rVar.getClass();
        Intrinsics.checkNotNullParameter(route, "route");
        rVar.b.m(route, null);
    }

    public final int a() {
        C4927s c4927s = this.b.f;
        int i = 0;
        if (c4927s != null && c4927s.isEmpty()) {
            return 0;
        }
        Iterator<E> it2 = c4927s.iterator();
        while (it2.hasNext()) {
            if (!(((C1291m) it2.next()).b instanceof D) && (i = i + 1) < 0) {
                kotlin.collections.B.o();
                throw null;
            }
        }
        return i;
    }

    public final void b(int i, Bundle from, K k) {
        androidx.navigation.internal.j jVar = this.b;
        B b = jVar.f.isEmpty() ? jVar.c : ((C1291m) jVar.f.last()).b;
        if (b == null) {
            throw new IllegalStateException("No current destination found. Ensure a navigation graph has been set for NavController " + this + '.');
        }
        b.g(i);
        kotlin.collections.V.c();
        Bundle source = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(from, "from");
        source.putAll(from);
        if (i == 0 && k != null) {
            String route = k.h;
            int i2 = k.c;
            if (i2 != -1 || route != null) {
                boolean z = k.d;
                if (route == null) {
                    if (i2 == -1 || !jVar.n(i2, z, false)) {
                        return;
                    }
                    jVar.b();
                    return;
                }
                Intrinsics.checkNotNullParameter(route, "route");
                Intrinsics.checkNotNullParameter(route, "route");
                if (jVar.o(route, z, false)) {
                    jVar.b();
                    return;
                }
                return;
            }
        }
        if (i == 0) {
            throw new IllegalArgumentException("Destination id == 0 can only be used in conjunction with a valid navOptions.popUpTo");
        }
        B bD = jVar.d(i, null);
        if (bD != null) {
            jVar.l(bD, source, k);
            return;
        }
        int i3 = B.e;
        throw new IllegalArgumentException("Navigation action/destination " + H1.a(this.c, i) + " cannot be found from the current destination " + b);
    }

    public final void c(String route, Function1 builder) {
        Intrinsics.checkNotNullParameter(route, "route");
        Intrinsics.checkNotNullParameter(builder, "builder");
        androidx.navigation.internal.j jVar = this.b;
        jVar.getClass();
        Intrinsics.checkNotNullParameter(route, "route");
        Intrinsics.checkNotNullParameter(builder, "builder");
        jVar.m(route, J1.c(builder));
    }

    public final void e() {
        Bundle from;
        Intent intent;
        if (a() != 1) {
            f();
            return;
        }
        Activity activity = this.d;
        Bundle extras = (activity == null || (intent = activity.getIntent()) == null) ? null : intent.getExtras();
        int[] intArray = extras != null ? extras.getIntArray("android-support-nav:controller:deepLinkIds") : null;
        androidx.navigation.internal.j jVar = this.b;
        int i = 0;
        if (intArray == null) {
            B bG = jVar.g();
            Intrinsics.d(bG);
            int i2 = bG.b.c;
            for (D d = bG.c; d != null; d = d.c) {
                int i3 = d.f.b;
                androidx.navigation.internal.m mVar = d.b;
                if (i3 != i2) {
                    kotlin.collections.V.c();
                    Bundle source = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
                    Intrinsics.checkNotNullParameter(source, "source");
                    if (activity != null && activity.getIntent() != null && activity.getIntent().getData() != null) {
                        Intent intent2 = activity.getIntent();
                        Intrinsics.checkNotNullExpressionValue(intent2, "getIntent(...)");
                        AbstractC3343g2.f(intent2, source);
                        D dJ = jVar.j();
                        Intent intent3 = activity.getIntent();
                        Intrinsics.checkNotNullExpressionValue(intent3, "getIntent(...)");
                        Intrinsics.checkNotNullParameter(intent3, "intent");
                        A aM = dJ.m(new com.quizlet.data.repository.set.f(intent3.getData(), intent3.getAction(), intent3.getType()), dJ);
                        if ((aM != null ? aM.b : null) != null && (from = aM.a.b(aM.b)) != null) {
                            Intrinsics.checkNotNullParameter(from, "from");
                            source.putAll(from);
                        }
                    }
                    z zVar = new z((H) this);
                    int i4 = mVar.c;
                    ArrayList arrayList = zVar.e;
                    arrayList.clear();
                    arrayList.add(new C1302y(i4, null));
                    if (zVar.d != null) {
                        zVar.c();
                    }
                    zVar.c.putExtra("android-support-nav:controller:deepLinkExtras", source);
                    zVar.a().e();
                    if (activity != null) {
                        activity.finish();
                        return;
                    }
                    return;
                }
                i2 = mVar.c;
            }
            return;
        }
        if (this.e) {
            Intrinsics.d(activity);
            Intent intent4 = activity.getIntent();
            Bundle extras2 = intent4.getExtras();
            Intrinsics.d(extras2);
            int[] intArray2 = extras2.getIntArray("android-support-nav:controller:deepLinkIds");
            Intrinsics.d(intArray2);
            ArrayList arrayListR = C4933y.R(intArray2);
            ArrayList parcelableArrayList = extras2.getParcelableArrayList("android-support-nav:controller:deepLinkArgs");
            if (arrayListR.size() < 2) {
                return;
            }
            int iIntValue = ((Number) kotlin.collections.G.A(arrayListR)).intValue();
            if (parcelableArrayList != null) {
            }
            D dH = jVar.h();
            Intrinsics.checkNotNullParameter(dH, "<this>");
            B bE = androidx.navigation.internal.j.e(iIntValue, dH, null, false);
            if (bE instanceof D) {
                int i5 = D.g;
                iIntValue = I1.f((D) bE).b.c;
            }
            B bG2 = jVar.g();
            if (bG2 == null || iIntValue != bG2.b.c) {
                return;
            }
            z zVar2 = new z((H) this);
            kotlin.collections.V.c();
            Bundle source2 = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
            Intrinsics.checkNotNullParameter(source2, "source");
            AbstractC3343g2.f(intent4, source2);
            Bundle from2 = extras2.getBundle("android-support-nav:controller:deepLinkExtras");
            if (from2 != null) {
                Intrinsics.checkNotNullParameter(from2, "from");
                source2.putAll(from2);
            }
            zVar2.c.putExtra("android-support-nav:controller:deepLinkExtras", source2);
            Iterator it2 = arrayListR.iterator();
            while (it2.hasNext()) {
                Object next = it2.next();
                int i6 = i + 1;
                if (i < 0) {
                    kotlin.collections.B.p();
                    throw null;
                }
                zVar2.e.add(new C1302y(((Number) next).intValue(), parcelableArrayList != null ? (Bundle) parcelableArrayList.get(i) : null));
                if (zVar2.d != null) {
                    zVar2.c();
                }
                i = i6;
            }
            zVar2.a().e();
            activity.finish();
        }
    }

    public final boolean f() {
        androidx.navigation.internal.j jVar = this.b;
        if (jVar.f.isEmpty()) {
            return false;
        }
        B bG = jVar.g();
        Intrinsics.d(bG);
        return jVar.n(bG.b.c, true, false) && jVar.b();
    }
}
