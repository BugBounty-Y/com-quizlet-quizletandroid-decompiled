package com.quizlet.remote.model.user;

import androidx.appcompat.app.y;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import com.quizlet.remote.service.E;
import com.quizlet.uicommon.ui.common.widgets.h;
import com.quizlet.uicommon.ui.common.widgets.i;
import io.reactivex.rxjava3.core.q;
import io.reactivex.rxjava3.disposables.b;
import io.reactivex.rxjava3.internal.operators.single.d;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h, q {
    public final Object a;
    public final Object b;

    public a(E service, com.quizlet.quizletandroid.managers.upgrade.a mapper) {
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.a = service;
        this.b = mapper;
    }

    @Override // io.reactivex.rxjava3.core.q
    public void a(b bVar) {
        ((q) this.a).a(bVar);
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.h
    public void b(i segment) {
        Intrinsics.checkNotNullParameter(segment, "checkedSegment");
        y yVar = (y) this.a;
        yVar.getClass();
        Intrinsics.checkNotNullParameter(segment, "segment");
        List list = (List) yVar.b;
        int iOrdinal = ((list.size() == 3) || segment != i.c) ? segment.ordinal() : 1;
        if (iOrdinal < 0 || iOrdinal >= list.size()) {
            throw new IllegalArgumentException(("Invalid segment " + segment + " for items: " + list).toString());
        }
        Object obj = list.get(iOrdinal);
        Function1 function1 = (Function1) this.b;
        if (function1 != null) {
            function1.invoke(obj);
        }
    }

    @Override // io.reactivex.rxjava3.core.q
    public void onError(Throwable th) {
        ((q) this.a).onError(th);
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        q qVar = (q) this.a;
        try {
            ((d) this.b).c.accept(obj);
            qVar.onSuccess(obj);
        } catch (Throwable th) {
            x7.b(th);
            qVar.onError(th);
        }
    }

    public a(d dVar, q qVar) {
        this.b = dVar;
        this.a = qVar;
    }

    public a() {
        this.a = new ArrayList();
        this.b = new ArrayList();
    }

    public a(y yVar, Function1 function1) {
        this.a = yVar;
        this.b = function1;
    }
}
