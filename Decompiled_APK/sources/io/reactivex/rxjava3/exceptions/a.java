package io.reactivex.rxjava3.exceptions;

import android.os.Build;
import android.os.Bundle;
import android.util.SizeF;
import androidx.compose.material3.J1;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0811n0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.internal.e;
import androidx.compose.ui.unit.g;
import androidx.glance.appwidget.AbstractC1218v;
import androidx.glance.appwidget.E0;
import androidx.glance.appwidget.F0;
import androidx.glance.appwidget.H0;
import androidx.glance.appwidget.I0;
import androidx.glance.appwidget.J0;
import androidx.glance.j;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public static final /* synthetic */ int c = 0;
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Type inference failed for: r5v26, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r5v30, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r5v31 */
    /* JADX WARN: Type inference failed for: r5v32, types: [java.util.ArrayList] */
    public static final void a(int i, long j, InterfaceC0806l interfaceC0806l, J0 j0, Function2 function2) {
        Collection collection;
        ?? B;
        Collection collectionB;
        J0 j02 = j0;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1526030150);
        Function2 function22 = function2;
        int i2 = i | (c0814p.f(j02) ? 4 : 2) | (c0814p.e(j) ? 32 : 16) | (c0814p.f(function22) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            if (j02 instanceof I0) {
                c0814p.Y(-1173540356);
                c0814p.p(false);
                collectionB = A.b(new g(j));
            } else {
                if (!(j02 instanceof H0)) {
                    c0814p.Y(-1173645715);
                    c0814p.p(false);
                    throw new NoWhenBranchMatchedException();
                }
                c0814p.Y(-1173538668);
                if (Build.VERSION.SDK_INT >= 31) {
                    c0814p.Y(-2019914396);
                    Bundle bundle = (Bundle) c0814p.j(AbstractC1218v.a);
                    c0814p.Y(-1173535336);
                    boolean zE = c0814p.e(j);
                    Object objI = c0814p.I();
                    if (zE || objI == C0804k.a) {
                        objI = new F0(0, j);
                        c0814p.i0(objI);
                    }
                    Function0 function0 = (Function0) objI;
                    c0814p.p(false);
                    ArrayList<SizeF> parcelableArrayList = bundle.getParcelableArrayList("appWidgetSizes");
                    if (parcelableArrayList == null || parcelableArrayList.isEmpty()) {
                        int i3 = bundle.getInt("appWidgetMinHeight", 0);
                        int i4 = bundle.getInt("appWidgetMaxHeight", 0);
                        int i5 = bundle.getInt("appWidgetMinWidth", 0);
                        int i6 = bundle.getInt("appWidgetMaxWidth", 0);
                        B = (i3 == 0 || i4 == 0 || i5 == 0 || i6 == 0) ? A.b(function0.invoke()) : B.j(new g(N5.c(i5, i4)), new g(N5.c(i6, i3)));
                    } else {
                        B = new ArrayList(C.q(parcelableArrayList, 10));
                        for (SizeF sizeF : parcelableArrayList) {
                            B.add(new g(N5.c(sizeF.getWidth(), sizeF.getHeight())));
                        }
                    }
                    c0814p.p(false);
                    collection = B;
                } else {
                    c0814p.Y(-2019826759);
                    Bundle bundle2 = (Bundle) c0814p.j(AbstractC1218v.a);
                    int i7 = bundle2.getInt("appWidgetMinHeight", 0);
                    int i8 = bundle2.getInt("appWidgetMaxWidth", 0);
                    g gVar = null;
                    g gVar2 = (i7 == 0 || i8 == 0) ? null : new g(N5.c(i8, i7));
                    int i9 = bundle2.getInt("appWidgetMaxHeight", 0);
                    int i10 = bundle2.getInt("appWidgetMinWidth", 0);
                    if (i9 != 0 && i10 != 0) {
                        gVar = new g(N5.c(i10, i9));
                    }
                    g[] elements = {gVar2, gVar};
                    Intrinsics.checkNotNullParameter(elements, "elements");
                    ArrayList arrayListZ = C4933y.z(elements);
                    boolean zIsEmpty = arrayListZ.isEmpty();
                    Collection collectionB2 = arrayListZ;
                    if (zIsEmpty) {
                        collectionB2 = A.b(new g(j));
                    }
                    c0814p.p(false);
                    collection = collectionB2;
                }
                c0814p.p(false);
                collectionB = collection;
            }
            List listG = CollectionsKt.G(collectionB);
            ArrayList arrayList = new ArrayList(C.q(listG, 10));
            Iterator it2 = listG.iterator();
            while (it2.hasNext()) {
                b(((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | (i2 & 896), ((g) it2.next()).a, c0814p, j02, function22);
                arrayList.add(Unit.a);
                j02 = j0;
                function22 = function2;
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new E0(j0, j, function2, i);
        }
    }

    public static final void b(int i, long j, InterfaceC0806l interfaceC0806l, J0 j0, Function2 function2) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-53921383);
        int i2 = (c0814p.e(j) ? 4 : 2) | i;
        if ((i & 48) == 0) {
            int i3 = i & 64;
            i2 |= c0814p.f(j0) ? 32 : 16;
        }
        if (((i2 | (c0814p.f(function2) ? 256 : 128)) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0776c.b(new C0811n0[]{j.a.a(new g(j))}, e.b(c0814p, -1209815847, new E0(function2, j, j0)), c0814p, 48);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new J1(j, j0, function2, i, 1);
        }
    }

    public final a c(Serializable serializable) {
        switch (this.a) {
            case 0:
                ((PrintStream) this.b).print(serializable);
                break;
            default:
                ((PrintWriter) this.b).print(serializable);
                break;
        }
        return this;
    }
}
