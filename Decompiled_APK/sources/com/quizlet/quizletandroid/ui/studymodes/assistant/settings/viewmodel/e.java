package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel;

import androidx.activity.compose.p;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ i k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            i iVar = this.k;
            com.quizlet.features.folders.addtofolder.viewmodel.usecase.c cVar = new com.quizlet.features.folders.addtofolder.viewmodel.usecase.c(K1.f(iVar.r.c()), new com.quizlet.features.flashcards.helpers.d(new kotlinx.coroutines.flow.Z(iVar.r.z), 5), new p(3, 5, (kotlin.coroutines.h) null), 2);
            d dVar = new d(iVar, null);
            this.j = 1;
            if (e0.i(cVar, dVar, this) == aVar) {
                return aVar;
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
