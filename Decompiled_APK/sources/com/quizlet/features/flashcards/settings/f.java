package com.quizlet.features.flashcards.settings;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.quizlet.features.flashcards.C4237k;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ j j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(j jVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        j jVar = this.j;
        com.quizlet.features.flashcards.logging.d dVar = jVar.c;
        dVar.getClass();
        com.quizlet.features.flashcards.logging.d.a(dVar, "options_button_tapped", null, null, null, 62);
        B7.d(jVar.g.c(), new C4237k(4), null, new e(jVar, 1), 2);
        return Unit.a;
    }
}
