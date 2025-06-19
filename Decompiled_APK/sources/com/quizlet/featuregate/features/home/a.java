package com.quizlet.featuregate.features.home;

import androidx.work.impl.model.c;
import com.google.android.gms.dynamite.d;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.single.g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements h {
    public static final a a = new a();

    public Object a(c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        return I1.b(b(cVar), cVar2);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Integer it2 = (Integer) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return Boolean.valueOf(it2.intValue() != 1);
    }

    public p b(c userProps) {
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        g gVarE = d.e(userProps.u());
        g gVarG = userProps.y().g(a);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return d.b(d.b(gVarE, gVarG), d.e(userProps.s()));
    }
}
