package com.quizlet.remote.model.feed;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.feed.FeedNoInternetException;
import com.quizlet.data.repository.activitycenter.b;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public final /* synthetic */ b j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, h hVar) {
        super(2, hVar);
        this.j = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws FeedNoInternetException {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        if (((com.quizlet.remote.connectivity.b) ((com.quizlet.data.connectivity.a) this.j.c)).a().a) {
            return Unit.a;
        }
        throw new FeedNoInternetException();
    }
}
