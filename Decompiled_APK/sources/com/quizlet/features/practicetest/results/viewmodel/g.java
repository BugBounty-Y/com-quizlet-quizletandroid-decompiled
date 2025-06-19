package com.quizlet.features.practicetest.results.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.ads.C3;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class g extends i implements Function2 {
    public int j;
    public final /* synthetic */ h k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(h hVar, String str, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        h hVar = this.k;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            C3 c3 = (C3) hVar.f.b;
            if (E.J((AbstractC5040y) c3.b, new com.quizlet.remote.model.practicetests.i(c3, hVar.j, this.l, null), this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        hVar.B();
        return Unit.a;
    }
}
