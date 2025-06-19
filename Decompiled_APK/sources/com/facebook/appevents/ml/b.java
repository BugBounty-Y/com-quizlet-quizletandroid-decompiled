package com.facebook.appevents.ml;

import java.util.HashMap;
import kotlin.Pair;
import kotlin.collections.C4933y;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public static final HashMap m = V.e(new Pair("embedding.weight", "embed.weight"), new Pair("dense1.weight", "fc1.weight"), new Pair("dense2.weight", "fc2.weight"), new Pair("dense3.weight", "fc3.weight"), new Pair("dense1.bias", "fc1.bias"), new Pair("dense2.bias", "fc2.bias"), new Pair("dense3.bias", "fc3.bias"));
    public final a a;
    public final a b;
    public final a c;
    public final a d;
    public final a e;
    public final a f;
    public final a g;
    public final a h;
    public final a i;
    public final a j;
    public final a k;
    public final HashMap l;

    public b(HashMap map) {
        Object obj = map.get("embed.weight");
        if (obj == null) {
            throw new IllegalStateException("Required value was null.");
        }
        this.a = (a) obj;
        Object obj2 = map.get("convs.0.weight");
        if (obj2 == null) {
            throw new IllegalStateException("Required value was null.");
        }
        this.b = f.r((a) obj2);
        Object obj3 = map.get("convs.1.weight");
        if (obj3 == null) {
            throw new IllegalStateException("Required value was null.");
        }
        this.c = f.r((a) obj3);
        Object obj4 = map.get("convs.2.weight");
        if (obj4 == null) {
            throw new IllegalStateException("Required value was null.");
        }
        this.d = f.r((a) obj4);
        Object obj5 = map.get("convs.0.bias");
        if (obj5 == null) {
            throw new IllegalStateException("Required value was null.");
        }
        this.e = (a) obj5;
        Object obj6 = map.get("convs.1.bias");
        if (obj6 == null) {
            throw new IllegalStateException("Required value was null.");
        }
        this.f = (a) obj6;
        Object obj7 = map.get("convs.2.bias");
        if (obj7 == null) {
            throw new IllegalStateException("Required value was null.");
        }
        this.g = (a) obj7;
        Object obj8 = map.get("fc1.weight");
        if (obj8 == null) {
            throw new IllegalStateException("Required value was null.");
        }
        this.h = f.q((a) obj8);
        Object obj9 = map.get("fc2.weight");
        if (obj9 == null) {
            throw new IllegalStateException("Required value was null.");
        }
        this.i = f.q((a) obj9);
        Object obj10 = map.get("fc1.bias");
        if (obj10 == null) {
            throw new IllegalStateException("Required value was null.");
        }
        this.j = (a) obj10;
        Object obj11 = map.get("fc2.bias");
        if (obj11 == null) {
            throw new IllegalStateException("Required value was null.");
        }
        this.k = (a) obj11;
        this.l = new HashMap();
        String[] elements = {c.a.a(), c.b.a()};
        Intrinsics.checkNotNullParameter(elements, "elements");
        for (String str : C4933y.T(elements)) {
            String strK = android.support.v4.media.session.a.k(str, ".weight");
            String strK2 = android.support.v4.media.session.a.k(str, ".bias");
            a aVar = (a) map.get(strK);
            a aVar2 = (a) map.get(strK2);
            if (aVar != null) {
                this.l.put(strK, f.q(aVar));
            }
            if (aVar2 != null) {
                this.l.put(strK2, aVar2);
            }
        }
    }

    public final a a(a dense, String[] texts, String task) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                Intrinsics.checkNotNullParameter(dense, "dense");
                Intrinsics.checkNotNullParameter(texts, "texts");
                Intrinsics.checkNotNullParameter(task, "task");
                a aVarD = f.d(f.g(texts, this.a), this.b);
                f.b(aVarD, this.e);
                f.m(aVarD);
                a aVarD2 = f.d(aVarD, this.c);
                f.b(aVarD2, this.f);
                f.m(aVarD2);
                a aVarK = f.k(aVarD2, 2);
                a aVarD3 = f.d(aVarK, this.d);
                f.b(aVarD3, this.g);
                f.m(aVarD3);
                a aVarK2 = f.k(aVarD, aVarD.a[1]);
                a aVarK3 = f.k(aVarK, aVarK.a[1]);
                a aVarK4 = f.k(aVarD3, aVarD3.a[1]);
                f.h(aVarK2);
                f.h(aVarK3);
                f.h(aVarK4);
                a aVarF = f.f(f.c(new a[]{aVarK2, aVarK3, aVarK4, dense}), this.h, this.j);
                f.m(aVarF);
                a aVarF2 = f.f(aVarF, this.i, this.k);
                f.m(aVarF2);
                HashMap map = this.l;
                a aVar = (a) map.get(task.concat(".weight"));
                a aVar2 = (a) map.get(task.concat(".bias"));
                if (aVar != null && aVar2 != null) {
                    a aVarF3 = f.f(aVarF2, aVar, aVar2);
                    f.p(aVarF3);
                    return aVarF3;
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }
}
