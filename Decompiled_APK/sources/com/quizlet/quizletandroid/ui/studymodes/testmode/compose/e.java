package com.quizlet.quizletandroid.ui.studymodes.testmode.compose;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3097a5;
import com.quizlet.quizletandroid.ui.studymodes.testmode.models.y;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t;
import com.quizlet.studiablemodels.StudiableMeteringData;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ t k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(t tVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = tVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        e eVar = new e(this.k, hVar);
        eVar.j = obj;
        return eVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((y) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        y upgradeEvent = (y) this.j;
        t tVar = this.k;
        tVar.getClass();
        Intrinsics.checkNotNullParameter(upgradeEvent, "upgradeEvent");
        tVar.o = AbstractC3097a5.d(upgradeEvent.a);
        StudiableMeteringData studiableMeteringDataD = AbstractC3097a5.d(upgradeEvent.b);
        tVar.p = studiableMeteringDataD;
        int i = tVar.r;
        StudiableMeteringData studiableMeteringData = tVar.o;
        boolean z = studiableMeteringData != null ? studiableMeteringData.f : false;
        ArrayList arrayList = tVar.q;
        if (arrayList != null) {
            E.A(p0.j(tVar), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.l(tVar, i, z, studiableMeteringDataD.f, arrayList, null), 3);
            return Unit.a;
        }
        Intrinsics.m("incorrectTermsIds");
        throw null;
    }
}
