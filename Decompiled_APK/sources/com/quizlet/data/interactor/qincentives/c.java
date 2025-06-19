package com.quizlet.data.interactor.qincentives;

import androidx.datastore.core.InterfaceC1076h;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.eventlogger.features.qincentives.QIncentivesEventLogger;
import com.quizlet.local.datastore.preferences.r0;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(e eVar, h hVar) {
        super(2, hVar);
        this.k = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            e eVar = this.k;
            ((QIncentivesEventLogger) eVar.c).b();
            com.google.firebase.crashlytics.internal.settings.b bVar = (com.google.firebase.crashlytics.internal.settings.b) eVar.b;
            this.j = 1;
            Object objD = S6.d((InterfaceC1076h) bVar.b, new r0(R6.a("should_get_free_trial"), null), this);
            if (objD != obj2) {
                objD = Unit.a;
            }
            if (objD == obj2) {
                return obj2;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
