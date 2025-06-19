package androidx.work.impl;

import android.content.Context;
import androidx.compose.ui.node.V;
import androidx.work.C1422c;
import androidx.work.C1437k;
import androidx.work.C1446u;
import androidx.work.N;
import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5027k0;

/* loaded from: classes.dex */
public final class F {
    public final androidx.work.impl.model.q a;
    public final Context b;
    public final String c;
    public final com.google.android.gms.internal.appset.e d;
    public final androidx.work.impl.utils.taskexecutor.c e;
    public final C1422c f;
    public final androidx.work.B g;
    public final C1433e h;
    public final WorkDatabase i;
    public final androidx.work.impl.model.t j;
    public final androidx.work.impl.model.c k;
    public final ArrayList l;
    public final String m;
    public final C5027k0 n;

    public F(V builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        androidx.work.impl.model.q qVar = (androidx.work.impl.model.q) builder.f;
        this.a = qVar;
        this.b = (Context) builder.h;
        String str = qVar.a;
        this.c = str;
        this.d = (com.google.android.gms.internal.appset.e) builder.i;
        this.e = (androidx.work.impl.utils.taskexecutor.c) builder.c;
        C1422c c1422c = (C1422c) builder.b;
        this.f = c1422c;
        this.g = c1422c.d;
        this.h = (C1433e) builder.d;
        WorkDatabase workDatabase = (WorkDatabase) builder.e;
        this.i = workDatabase;
        this.j = workDatabase.u();
        this.k = workDatabase.f();
        ArrayList arrayList = (ArrayList) builder.g;
        this.l = arrayList;
        this.m = android.support.v4.media.session.a.t(android.support.v4.media.session.a.y("Work [ id=", str, ", tags={ "), CollectionsKt.S(arrayList, ",", null, null, null, 62), " } ]");
        this.n = kotlinx.coroutines.E.d();
    }

    /* JADX WARN: Removed duplicated region for block: B:84:0x029e  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(final androidx.work.impl.F r17, kotlin.coroutines.jvm.internal.c r18) throws java.lang.IllegalAccessException, java.lang.InstantiationException, java.lang.IllegalArgumentException, java.lang.reflect.InvocationTargetException {
        /*
            Method dump skipped, instructions count: 710
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.F.a(androidx.work.impl.F, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void b(int i) {
        N n = N.a;
        androidx.work.impl.model.t tVar = this.j;
        String str = this.c;
        tVar.y(n, str);
        this.g.getClass();
        tVar.w(System.currentTimeMillis(), str);
        tVar.t(this.a.v, str);
        tVar.q(-1L, str);
        tVar.z(i, str);
    }

    public final void c() {
        this.g.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        androidx.work.impl.model.t tVar = this.j;
        String str = this.c;
        tVar.w(jCurrentTimeMillis, str);
        tVar.y(N.a, str);
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) tVar.a;
        workDatabase_Impl.b();
        androidx.work.impl.model.h hVar = (androidx.work.impl.model.h) tVar.j;
        androidx.sqlite.db.framework.i iVarA = hVar.a();
        iVarA.g(1, str);
        try {
            workDatabase_Impl.c();
            try {
                iVarA.a();
                workDatabase_Impl.p();
                hVar.n(iVarA);
                tVar.t(this.a.v, str);
                workDatabase_Impl.b();
                hVar = (androidx.work.impl.model.h) tVar.f;
                iVarA = hVar.a();
                iVarA.g(1, str);
                try {
                    workDatabase_Impl.c();
                    try {
                        iVarA.a();
                        workDatabase_Impl.p();
                        hVar.n(iVarA);
                        tVar.q(-1L, str);
                    } finally {
                    }
                } finally {
                }
            } finally {
            }
        } finally {
        }
    }

    public final void d(androidx.work.x result) {
        Intrinsics.checkNotNullParameter(result, "result");
        String str = this.c;
        ArrayList arrayListK = kotlin.collections.B.k(str);
        while (true) {
            boolean zIsEmpty = arrayListK.isEmpty();
            androidx.work.impl.model.t tVar = this.j;
            if (zIsEmpty) {
                C1437k c1437k = ((C1446u) result).a;
                Intrinsics.checkNotNullExpressionValue(c1437k, "failure.outputData");
                tVar.t(this.a.v, str);
                tVar.x(str, c1437k);
                return;
            }
            String str2 = (String) kotlin.collections.G.A(arrayListK);
            if (tVar.n(str2) != N.f) {
                tVar.y(N.d, str2);
            }
            arrayListK.addAll(this.k.e(str2));
        }
    }
}
