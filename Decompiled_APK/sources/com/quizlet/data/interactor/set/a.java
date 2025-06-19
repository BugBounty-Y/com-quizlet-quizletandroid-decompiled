package com.quizlet.data.interactor.set;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3738u6;
import com.google.firebase.messaging.p;
import com.quizlet.assembly.compose.listitems.r;
import com.quizlet.data.model.C4160q1;
import com.quizlet.data.repository.set.f;
import com.quizlet.quizletandroid.ui.activitycenter.views.i;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.j;
import io.reactivex.rxjava3.internal.operators.completable.m;
import io.reactivex.rxjava3.internal.operators.single.g;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ c b;

    public /* synthetic */ a(c cVar, int i) {
        this.a = i;
        this.b = cVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                final f fVar = (f) this.b.a;
                final int i = 0;
                final int i2 = 0;
                m mVar = new m(new io.reactivex.rxjava3.internal.operators.flowable.b(new j() { // from class: com.quizlet.data.repository.set.a
                    @Override // io.reactivex.rxjava3.functions.j
                    public final Object get() {
                        switch (i) {
                            case 0:
                                final f fVar2 = fVar;
                                final int i3 = 1;
                                return AbstractC3738u6.b((com.quizlet.data.connectivity.a) fVar2.c, new Function0() { // from class: com.quizlet.data.repository.set.c
                                    @Override // kotlin.jvm.functions.Function0
                                    public final Object invoke() {
                                        switch (i3) {
                                            case 0:
                                                com.quizlet.remote.model.set.d dVar = (com.quizlet.remote.model.set.d) ((p) fVar2.b).b;
                                                com.quizlet.remote.model.set.a aVar = (com.quizlet.remote.model.set.a) dVar.a;
                                                g gVarG = aVar.a.b(com.quizlet.remote.model.set.a.c.a(), com.quizlet.remote.model.set.a.e.a()).g(new i(dVar, 9));
                                                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                                                return gVarG;
                                            default:
                                                com.quizlet.remote.model.set.d dVar2 = (com.quizlet.remote.model.set.d) ((p) fVar2.b).b;
                                                com.quizlet.remote.model.set.a aVar2 = (com.quizlet.remote.model.set.a) dVar2.a;
                                                g gVarG2 = aVar2.a.c(com.quizlet.remote.model.set.a.d.a(), com.quizlet.remote.model.set.a.e.a()).g(new com.quizlet.local.ormlite.models.term.b(dVar2, 17));
                                                Intrinsics.checkNotNullExpressionValue(gVarG2, "map(...)");
                                                return gVarG2;
                                        }
                                    }
                                }, new r(20));
                            default:
                                final f fVar3 = fVar;
                                final int i4 = 0;
                                return AbstractC3738u6.b((com.quizlet.data.connectivity.a) fVar3.c, new Function0() { // from class: com.quizlet.data.repository.set.c
                                    @Override // kotlin.jvm.functions.Function0
                                    public final Object invoke() {
                                        switch (i4) {
                                            case 0:
                                                com.quizlet.remote.model.set.d dVar = (com.quizlet.remote.model.set.d) ((p) fVar3.b).b;
                                                com.quizlet.remote.model.set.a aVar = (com.quizlet.remote.model.set.a) dVar.a;
                                                g gVarG = aVar.a.b(com.quizlet.remote.model.set.a.c.a(), com.quizlet.remote.model.set.a.e.a()).g(new i(dVar, 9));
                                                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                                                return gVarG;
                                            default:
                                                com.quizlet.remote.model.set.d dVar2 = (com.quizlet.remote.model.set.d) ((p) fVar3.b).b;
                                                com.quizlet.remote.model.set.a aVar2 = (com.quizlet.remote.model.set.a) dVar2.a;
                                                g gVarG2 = aVar2.a.c(com.quizlet.remote.model.set.a.d.a(), com.quizlet.remote.model.set.a.e.a()).g(new com.quizlet.local.ormlite.models.term.b(dVar2, 17));
                                                Intrinsics.checkNotNullExpressionValue(gVarG2, "map(...)");
                                                return gVarG2;
                                        }
                                    }
                                }, new r(19));
                        }
                    }
                }, 4), new h() { // from class: com.quizlet.data.repository.set.b
                    @Override // io.reactivex.rxjava3.functions.h
                    public final Object apply(Object obj) {
                        Throwable it2 = (Throwable) obj;
                        switch (i2) {
                            case 0:
                                Intrinsics.checkNotNullParameter(it2, "it");
                                ((org.slf4j.b) fVar.d).j("Error from remote", it2);
                                return K.a;
                            default:
                                Intrinsics.checkNotNullParameter(it2, "it");
                                ((org.slf4j.b) fVar.d).j("Error from remote", it2);
                                return new C4160q1(K.a, null, null);
                        }
                    }
                }, null, 2);
                Intrinsics.checkNotNullExpressionValue(mVar, "onErrorReturn(...)");
                return mVar;
            default:
                final f fVar2 = (f) this.b.a;
                final int i3 = 1;
                final int i4 = 1;
                m mVar2 = new m(new io.reactivex.rxjava3.internal.operators.flowable.b(new j() { // from class: com.quizlet.data.repository.set.a
                    @Override // io.reactivex.rxjava3.functions.j
                    public final Object get() {
                        switch (i3) {
                            case 0:
                                final f fVar22 = fVar2;
                                final int i32 = 1;
                                return AbstractC3738u6.b((com.quizlet.data.connectivity.a) fVar22.c, new Function0() { // from class: com.quizlet.data.repository.set.c
                                    @Override // kotlin.jvm.functions.Function0
                                    public final Object invoke() {
                                        switch (i32) {
                                            case 0:
                                                com.quizlet.remote.model.set.d dVar = (com.quizlet.remote.model.set.d) ((p) fVar22.b).b;
                                                com.quizlet.remote.model.set.a aVar = (com.quizlet.remote.model.set.a) dVar.a;
                                                g gVarG = aVar.a.b(com.quizlet.remote.model.set.a.c.a(), com.quizlet.remote.model.set.a.e.a()).g(new i(dVar, 9));
                                                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                                                return gVarG;
                                            default:
                                                com.quizlet.remote.model.set.d dVar2 = (com.quizlet.remote.model.set.d) ((p) fVar22.b).b;
                                                com.quizlet.remote.model.set.a aVar2 = (com.quizlet.remote.model.set.a) dVar2.a;
                                                g gVarG2 = aVar2.a.c(com.quizlet.remote.model.set.a.d.a(), com.quizlet.remote.model.set.a.e.a()).g(new com.quizlet.local.ormlite.models.term.b(dVar2, 17));
                                                Intrinsics.checkNotNullExpressionValue(gVarG2, "map(...)");
                                                return gVarG2;
                                        }
                                    }
                                }, new r(20));
                            default:
                                final f fVar3 = fVar2;
                                final int i42 = 0;
                                return AbstractC3738u6.b((com.quizlet.data.connectivity.a) fVar3.c, new Function0() { // from class: com.quizlet.data.repository.set.c
                                    @Override // kotlin.jvm.functions.Function0
                                    public final Object invoke() {
                                        switch (i42) {
                                            case 0:
                                                com.quizlet.remote.model.set.d dVar = (com.quizlet.remote.model.set.d) ((p) fVar3.b).b;
                                                com.quizlet.remote.model.set.a aVar = (com.quizlet.remote.model.set.a) dVar.a;
                                                g gVarG = aVar.a.b(com.quizlet.remote.model.set.a.c.a(), com.quizlet.remote.model.set.a.e.a()).g(new i(dVar, 9));
                                                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                                                return gVarG;
                                            default:
                                                com.quizlet.remote.model.set.d dVar2 = (com.quizlet.remote.model.set.d) ((p) fVar3.b).b;
                                                com.quizlet.remote.model.set.a aVar2 = (com.quizlet.remote.model.set.a) dVar2.a;
                                                g gVarG2 = aVar2.a.c(com.quizlet.remote.model.set.a.d.a(), com.quizlet.remote.model.set.a.e.a()).g(new com.quizlet.local.ormlite.models.term.b(dVar2, 17));
                                                Intrinsics.checkNotNullExpressionValue(gVarG2, "map(...)");
                                                return gVarG2;
                                        }
                                    }
                                }, new r(19));
                        }
                    }
                }, 4), new h() { // from class: com.quizlet.data.repository.set.b
                    @Override // io.reactivex.rxjava3.functions.h
                    public final Object apply(Object obj) {
                        Throwable it2 = (Throwable) obj;
                        switch (i4) {
                            case 0:
                                Intrinsics.checkNotNullParameter(it2, "it");
                                ((org.slf4j.b) fVar2.d).j("Error from remote", it2);
                                return K.a;
                            default:
                                Intrinsics.checkNotNullParameter(it2, "it");
                                ((org.slf4j.b) fVar2.d).j("Error from remote", it2);
                                return new C4160q1(K.a, null, null);
                        }
                    }
                }, null, 2);
                Intrinsics.checkNotNullExpressionValue(mVar2, "onErrorReturn(...)");
                return mVar2;
        }
    }
}
