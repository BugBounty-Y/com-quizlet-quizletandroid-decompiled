package com.quizlet.features.setpage.termlist.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.work.impl.model.v;
import com.facebook.appevents.iap.u;
import com.google.android.gms.internal.mlkit_vision_common.C;
import com.quizlet.features.setpage.termlist.data.m;
import com.quizlet.features.setpage.termlist.data.n;
import com.quizlet.features.setpage.termlist.data.o;
import com.quizlet.features.setpage.termlist.data.p;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes3.dex */
public final class j extends w0 {
    public final com.google.android.gms.internal.appset.e b;
    public final com.quizlet.data.interactor.course.a c;
    public final com.quizlet.shared.usecase.folderstudymaterials.d d;
    public final com.quizlet.quizletandroid.managers.audio.h e;
    public final v f;
    public final long g;
    public final s0 h;
    public final d0 i;
    public final s0 j;
    public y0 k;

    public j(m0 savedStateHandle, com.google.android.gms.internal.appset.e getTermsWithStarredUseCase, com.quizlet.data.interactor.course.a termListSortOptionUseCase, com.quizlet.shared.usecase.folderstudymaterials.d termListSortUseCase, com.quizlet.quizletandroid.managers.audio.h audioManager, v setInSelectedTermsModeUseCase) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(getTermsWithStarredUseCase, "getTermsWithStarredUseCase");
        Intrinsics.checkNotNullParameter(termListSortOptionUseCase, "termListSortOptionUseCase");
        Intrinsics.checkNotNullParameter(termListSortUseCase, "termListSortUseCase");
        Intrinsics.checkNotNullParameter(audioManager, "audioManager");
        Intrinsics.checkNotNullParameter(setInSelectedTermsModeUseCase, "setInSelectedTermsModeUseCase");
        this.b = getTermsWithStarredUseCase;
        this.c = termListSortOptionUseCase;
        this.d = termListSortUseCase;
        this.e = audioManager;
        this.f = setInSelectedTermsModeUseCase;
        Long l = (Long) savedStateHandle.a("setId");
        this.g = l != null ? l.longValue() : 0L;
        this.h = e0.c(o.a);
        this.i = e0.b(0, 0, null, 7);
        this.j = e0.c(K.a);
    }

    public static final List A(j jVar, m sortOption) {
        List terms = (List) jVar.j.getValue();
        jVar.d.getClass();
        Intrinsics.checkNotNullParameter(terms, "terms");
        Intrinsics.checkNotNullParameter(sortOption, "sortOption");
        int iOrdinal = sortOption.ordinal();
        if (iOrdinal == 0) {
            return terms;
        }
        if (iOrdinal == 1) {
            return CollectionsKt.n0(terms, new com.google.zxing.aztec.encoder.c(17));
        }
        throw new NoWhenBranchMatchedException();
    }

    public final void B(C event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (event instanceof com.quizlet.features.setpage.termlist.data.h) {
            com.quizlet.features.setpage.termlist.data.h hVar = (com.quizlet.features.setpage.termlist.data.h) event;
            E.A(p0.j(this), u.d(), null, new i(this, hVar.a, hVar.b, null), 2);
            return;
        }
        if (event instanceof com.quizlet.features.setpage.termlist.data.e) {
            E.A(p0.j(this), null, null, new d(this, null), 3);
            return;
        }
        if (event instanceof com.quizlet.features.setpage.termlist.data.g) {
            E.A(p0.j(this), null, null, new g(this, ((com.quizlet.features.setpage.termlist.data.g) event).a, null), 3);
            return;
        }
        if (event instanceof com.quizlet.features.setpage.termlist.data.f) {
            com.quizlet.features.setpage.termlist.data.f fVar = (com.quizlet.features.setpage.termlist.data.f) event;
            C(fVar.a, A.b(fVar.b), fVar.c);
        } else if (event instanceof com.quizlet.features.setpage.termlist.data.c) {
            com.quizlet.features.setpage.termlist.data.c cVar = (com.quizlet.features.setpage.termlist.data.c) event;
            C(cVar.a, B.j(cVar.b, cVar.c), cVar.d);
        } else {
            if (!(event instanceof com.quizlet.features.setpage.termlist.data.d)) {
                throw new NoWhenBranchMatchedException();
            }
            E.A(p0.j(this), null, null, new h(this, ((com.quizlet.features.setpage.termlist.data.d) event).a, null), 3);
        }
    }

    public final void C(long j, List list, boolean z) {
        D(j, z);
        y0 y0Var = this.k;
        if (y0Var != null) {
            y0Var.j(null);
        }
        if (z) {
            this.k = E.A(p0.j(this), new e(this, j), null, new f(list, this, j, null), 2);
        }
    }

    public final void D(long j, boolean z) {
        List<com.quizlet.features.setpage.termlist.data.j> list;
        Object value;
        n nVar;
        ArrayList arrayList;
        s0 s0Var = this.h;
        Object value2 = s0Var.getValue();
        n nVar2 = value2 instanceof n ? (n) value2 : null;
        if (nVar2 == null || (list = nVar2.a) == null) {
            return;
        }
        do {
            value = s0Var.getValue();
            p pVar = (p) value;
            Intrinsics.e(pVar, "null cannot be cast to non-null type com.quizlet.features.setpage.termlist.data.TermsViewState.Content");
            nVar = (n) pVar;
            arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
            for (com.quizlet.features.setpage.termlist.data.j jVar : list) {
                long j2 = jVar.a;
                if (j2 == j) {
                    com.quizlet.features.infra.models.a word = jVar.b;
                    Intrinsics.checkNotNullParameter(word, "word");
                    jVar = new com.quizlet.features.setpage.termlist.data.j(j2, word, jVar.c, jVar.d, jVar.e, jVar.f, z);
                }
                arrayList.add(jVar);
            }
        } while (!s0Var.k(value, n.a(nVar, arrayList, null, null, false, 30)));
    }
}
