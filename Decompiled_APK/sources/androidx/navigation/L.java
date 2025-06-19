package androidx.navigation;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final class L {
    public final J a;
    public boolean b;
    public boolean c;
    public int d;
    public String e;
    public boolean f;
    public boolean g;

    public L() {
        J j = new J();
        j.c = -1;
        j.g = -1;
        j.h = -1;
        this.a = j;
        this.d = -1;
    }

    public static void b(L l) {
        C1265a popUpToBuilder = new C1265a(9);
        l.getClass();
        Intrinsics.checkNotNullParameter("practiceTest", "route");
        Intrinsics.checkNotNullParameter(popUpToBuilder, "popUpToBuilder");
        if (StringsKt.O("practiceTest")) {
            throw new IllegalArgumentException("Cannot pop up to an empty route");
        }
        l.e = "practiceTest";
        l.d = -1;
        l.f = false;
        Y y = new Y();
        popUpToBuilder.invoke(y);
        l.f = y.a;
        l.g = y.b;
    }

    public final void a(int i, Function1 popUpToBuilder) {
        Intrinsics.checkNotNullParameter(popUpToBuilder, "popUpToBuilder");
        this.d = i;
        this.f = false;
        Y y = new Y();
        popUpToBuilder.invoke(y);
        this.f = y.a;
        this.g = y.b;
    }
}
