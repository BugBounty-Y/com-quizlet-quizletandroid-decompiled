package com.quizlet.quizletandroid.ui.base.viewmodel;

import androidx.lifecycle.Y;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.quizlet.analytics.marketing.e;
import com.quizlet.infra.legacysyncengine.datasources.c;
import com.quizlet.viewmodel.b;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.internal.functions.d;
import io.reactivex.rxjava3.internal.observers.h;
import io.reactivex.rxjava3.internal.operators.observable.C;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a extends b implements com.quizlet.infra.legacysyncengine.datasources.b {
    public final c c;
    public final Y d;
    public final Y e;
    public final Y f;

    public a(c dataSource) {
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        this.c = dataSource;
        this.d = new Y();
        this.e = new Y();
        this.f = new Y();
        dataSource.e(this);
        B();
    }

    public final void B() {
        i iVarD = this.c.d();
        e eVar = new e(this, 23);
        io.reactivex.rxjava3.internal.functions.b bVar = d.c;
        iVarD.getClass();
        C c = new C(iVarD, eVar, bVar);
        Intrinsics.checkNotNullExpressionValue(c, "doOnSubscribe(...)");
        h hVarD = B7.d(c, new com.quizlet.login.common.navigation.d(1, timber.log.c.a, timber.log.a.class, "e", "e(Ljava/lang/Throwable;)V", 0, 20), null, new com.quizlet.login.common.navigation.d(1, this, a.class, "refreshComplete", "refreshComplete(Lcom/quizlet/infra/legacysyncengine/net/request/PagedRequestCompletionInfo;)V", 0, 21), 2);
        Intrinsics.checkNotNullParameter(hVarD, "<this>");
        A(hVarD);
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.b
    public final void h(List list) {
        this.d.j(list);
    }

    @Override // com.quizlet.viewmodel.b, androidx.lifecycle.w0
    public final void z() {
        super.z();
        this.c.a(this);
    }
}
