package com.quizlet.features.infra.folder.menu.composable;

import android.os.Bundle;
import androidx.compose.runtime.L0;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.assembly.compose.modals.y;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ x k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(x xVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = xVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        f fVar = new f(this.k, hVar);
        fVar.j = obj;
        return fVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((com.quizlet.features.infra.folder.menu.screenstates.a) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.infra.folder.menu.screenstates.a aVar2 = (com.quizlet.features.infra.folder.menu.screenstates.a) this.j;
        Bundle bundleA = AbstractC3206m6.a(new Pair("NewTagModalArgs.ARG_PARENT_FOLDER_ID", new Long(aVar2.a)), new Pair("NewTagModalArgs.ARG_CURRENT_FOLDER_TAGS", aVar2.b.toArray(new String[0])));
        x xVar = this.k;
        xVar.c = bundleA;
        ((L0) xVar.a).setValue(y.a);
        return Unit.a;
    }
}
