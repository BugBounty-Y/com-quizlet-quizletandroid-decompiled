package com.quizlet.quizletandroid.ui.library;

import androidx.datastore.core.InterfaceC1076h;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.quizlet.data.model.EnumC4164s0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class b0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ c0 k;
    public final /* synthetic */ EnumC4164s0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b0(EnumC4164s0 enumC4164s0, c0 c0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0Var;
        this.l = enumC4164s0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b0(this.l, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            com.google.firebase.crashlytics.internal.common.j jVar = this.k.l;
            this.j = 1;
            jVar.getClass();
            int iOrdinal = this.l.ordinal();
            com.google.firebase.crashlytics.internal.common.j jVar2 = (com.google.firebase.crashlytics.internal.common.j) jVar.b;
            Object objD = S6.d((InterfaceC1076h) jVar2.b, new com.quizlet.local.datastore.preferences.N(R6.c("lastLibraryTabVisitedKey"), iOrdinal, null), this);
            if (objD != obj2) {
                objD = Unit.a;
            }
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
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
