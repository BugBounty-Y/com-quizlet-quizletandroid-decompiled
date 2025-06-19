package com.quizlet.features.setpage.termlist.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public j j;
    public Iterator k;
    public int l;
    public final /* synthetic */ List m;
    public final /* synthetic */ j n;
    public final /* synthetic */ long o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(List list, j jVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = list;
        this.n = jVar;
        this.o = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Iterator it2;
        j jVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.l;
        long j = this.o;
        j jVar2 = this.n;
        try {
            try {
                if (i == 0) {
                    Z.e(obj);
                    it2 = CollectionsKt.J(this.m).iterator();
                    jVar = jVar2;
                } else {
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    it2 = this.k;
                    jVar = this.j;
                    Z.e(obj);
                }
                while (it2.hasNext()) {
                    io.reactivex.rxjava3.internal.operators.completable.a aVarA = jVar.e.a((String) it2.next());
                    this.j = jVar;
                    this.k = it2;
                    this.l = 1;
                    if (I1.a(aVarA, this) == aVar) {
                        return aVar;
                    }
                }
            } catch (IOException e) {
                timber.log.c.a.e(e);
            }
            return Unit.a;
        } finally {
            jVar2.D(j, false);
        }
    }
}
