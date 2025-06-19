package com.quizlet.quizletandroid.data.management;

import com.google.android.datatransport.cct.internal.s;
import com.quizlet.db.data.models.persisted.DBStudySet;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.maybe.j;
import io.reactivex.rxjava3.internal.operators.observable.N;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements h {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ s c;
    public final /* synthetic */ com.quizlet.qutils.data.offline.d d;
    public final /* synthetic */ long e;

    public /* synthetic */ g(boolean z, s sVar, com.quizlet.qutils.data.offline.d dVar, long j, int i) {
        this.a = i;
        this.b = z;
        this.c = sVar;
        this.d = dVar;
        this.e = j;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                DBStudySet set = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(set, "set");
                boolean z = this.b;
                long j = this.e;
                com.quizlet.qutils.data.offline.d dVar = this.d;
                s sVar = this.c;
                if (!z) {
                    return sVar.e(set, dVar, j);
                }
                j jVar = new j(sVar.e(set, dVar, j), new f(sVar, 0), 0);
                Intrinsics.checkNotNullExpressionValue(jVar, "flatMap(...)");
                return jVar;
            default:
                List setList = (List) obj;
                Intrinsics.checkNotNullParameter(setList, "setList");
                return new N(i.o(setList), new g(this.b, this.c, this.d, this.e, 0), false).x(16);
        }
    }
}
