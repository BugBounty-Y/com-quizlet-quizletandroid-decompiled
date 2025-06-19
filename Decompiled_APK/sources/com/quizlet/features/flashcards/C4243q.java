package com.quizlet.features.flashcards;

import android.content.Context;
import android.content.Intent;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.y0;

/* renamed from: com.quizlet.features.flashcards.q, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4243q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.features.flashcards.autoplay.o k;
    public final /* synthetic */ Context l;
    public final /* synthetic */ androidx.lifecycle.J m;
    public final /* synthetic */ S n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4243q(Context context, androidx.lifecycle.J j, S s, com.quizlet.features.flashcards.autoplay.o oVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oVar;
        this.l = context;
        this.m = j;
        this.n = s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4243q c4243q = new C4243q(this.l, this.m, this.n, this.k, hVar);
        c4243q.j = obj;
        return c4243q;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4243q) create((com.quizlet.features.flashcards.autoplay.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        y0 y0Var;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.flashcards.autoplay.b bVar = (com.quizlet.features.flashcards.autoplay.b) this.j;
        boolean z = bVar instanceof com.quizlet.features.flashcards.autoplay.q;
        Context context = this.l;
        com.quizlet.features.flashcards.autoplay.o oVar = this.k;
        if (z) {
            Intrinsics.d(context);
            com.quizlet.features.flashcards.autoplay.q startingData = (com.quizlet.features.flashcards.autoplay.q) bVar;
            oVar.getClass();
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(startingData, "startingData");
            oVar.b = startingData;
            FlashcardsAutoplayService flashcardsAutoplayService = oVar.c;
            if (flashcardsAutoplayService == null || !flashcardsAutoplayService.k) {
                int i = FlashcardsAutoplayService.o;
                context.bindService(AbstractC4178x.b(context, "context", context, FlashcardsAutoplayService.class), oVar.d, 1);
                Intrinsics.checkNotNullParameter(context, "context");
                context.startForegroundService(new Intent(context, (Class<?>) FlashcardsAutoplayService.class));
            } else {
                flashcardsAutoplayService.h(startingData);
            }
            oVar.a.f(this.m, new com.quizlet.ads.ui.fragments.c(new C4232f(this.n, 1)));
        } else if (Intrinsics.b(bVar, com.quizlet.features.flashcards.autoplay.f.a)) {
            Intrinsics.d(context);
            oVar.getClass();
            Intrinsics.checkNotNullParameter(context, "context");
            FlashcardsAutoplayService flashcardsAutoplayService2 = oVar.c;
            if (flashcardsAutoplayService2 != null ? flashcardsAutoplayService2.k : false) {
                context.unbindService(oVar.d);
                int i2 = FlashcardsAutoplayService.o;
                Intrinsics.checkNotNullParameter(context, "context");
                context.stopService(new Intent(context, (Class<?>) FlashcardsAutoplayService.class));
                oVar.c = null;
                oVar.b = null;
            }
        } else {
            if (!Intrinsics.b(bVar, com.quizlet.features.flashcards.autoplay.p.a)) {
                throw new NoWhenBranchMatchedException();
            }
            FlashcardsAutoplayService flashcardsAutoplayService3 = oVar.c;
            if (flashcardsAutoplayService3 != null && (y0Var = flashcardsAutoplayService3.n) != null) {
                y0Var.j(null);
            }
        }
        return Unit.a;
    }
}
