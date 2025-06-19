package com.quizlet.features.match.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.match.data.T;
import com.quizlet.features.match.settings.MatchSettingsData;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ int j;
    public final /* synthetic */ h k;
    public final /* synthetic */ MatchSettingsData l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(int i, h hVar, MatchSettingsData matchSettingsData, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.j = i;
        this.k = hVar;
        this.l = matchSettingsData;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        int i = this.j;
        h hVar = this.k;
        if (i == 0) {
            hVar.c.o(T.a);
        } else if (this.l.a) {
            hVar.c.o(T.c);
        } else {
            hVar.c.o(T.b);
        }
        return Unit.a;
    }
}
