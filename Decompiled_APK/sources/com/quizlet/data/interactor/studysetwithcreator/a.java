package com.quizlet.data.interactor.studysetwithcreator;

import com.quizlet.data.repository.studysetwithcreator.d;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.observable.E;
import kotlin.jvm.internal.Intrinsics;
import org.slf4j.b;

/* loaded from: classes2.dex */
public final class a implements h {
    public final d a;

    public a(d repository, int i) {
        switch (i) {
            case 1:
                this.a = repository;
                break;
            default:
                Intrinsics.checkNotNullParameter(repository, "repository");
                this.a = repository;
                break;
        }
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Throwable e = (Throwable) obj;
        Intrinsics.checkNotNullParameter(e, "e");
        ((b) this.a.d).j("no cached object", e);
        return E.a;
    }
}
