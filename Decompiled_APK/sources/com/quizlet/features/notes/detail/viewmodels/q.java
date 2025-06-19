package com.quizlet.features.notes.detail.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.quizlet.data.model.FlashcardsInfo;
import com.quizlet.data.model.NotesToValueInfo;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ v k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(v vVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = vVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new q(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((q) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        v vVar = this.k;
        if (i == 0) {
            Z.e(obj);
            if (vVar.v != null) {
                this.j = 1;
                if (vVar.D(false, this) == aVar) {
                    return aVar;
                }
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        NotesToValueInfo notesToValueInfo = vVar.v;
        if (notesToValueInfo == null) {
            Intrinsics.m("magicNotes");
            throw null;
        }
        FlashcardsInfo flashcardsInfo = notesToValueInfo.f;
        if (flashcardsInfo != null) {
            E.A(p0.j(vVar), vVar.w, null, new s(vVar, flashcardsInfo, null), 2);
        }
        return Unit.a;
    }
}
