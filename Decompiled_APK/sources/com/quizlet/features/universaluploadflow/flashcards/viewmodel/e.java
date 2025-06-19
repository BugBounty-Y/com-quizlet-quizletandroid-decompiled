package com.quizlet.features.universaluploadflow.flashcards.viewmodel;

import androidx.compose.foundation.gestures.l1;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.braze.requests.framework.m;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.quizlet.data.model.m2;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.model.UniversalUploadFlowEventLog;
import com.quizlet.features.universaluploadflow.flashcards.data.f;
import com.quizlet.features.universaluploadflow.flashcards.data.g;
import com.quizlet.features.universaluploadflow.flashcards.data.h;
import com.quizlet.features.universaluploadflow.flashcards.data.i;
import com.quizlet.features.universaluploadflow.flashcards.data.j;
import com.quizlet.features.universaluploadflow.flashcards.data.n;
import com.quizlet.features.universaluploadflow.flashcards.data.p;
import com.quizlet.features.universaluploadflow.flashcards.data.q;
import com.quizlet.features.universaluploadflow.flashcards.data.r;
import com.quizlet.generated.enums.EnumC4471c0;
import com.quizlet.generated.enums.EnumC4483g0;
import com.quizlet.generated.enums.EnumC4503n;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes3.dex */
public final class e extends w0 implements a {
    public final m0 b;
    public final com.google.android.gms.internal.appset.e c;
    public final l1 d;
    public final com.quizlet.features.universaluploadflow.logging.b e;
    public final long f;
    public final s0 g;
    public final d0 h;
    public final m2 i;
    public final C4203d j;
    public p k;
    public y0 l;

    public e(m0 savedStateHandle, com.google.android.gms.internal.appset.e uploadContentUseCase, l1 getFlashcardSetsUiUseCase, com.quizlet.features.universaluploadflow.logging.b eventLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(uploadContentUseCase, "uploadContentUseCase");
        Intrinsics.checkNotNullParameter(getFlashcardSetsUiUseCase, "getFlashcardSetsUiUseCase");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.b = savedStateHandle;
        this.c = uploadContentUseCase;
        this.d = getFlashcardSetsUiUseCase;
        this.e = eventLogger;
        this.f = 300L;
        this.g = e0.c(r.a);
        this.h = e0.b(0, 1, null, 5);
        Object objA = savedStateHandle.a("source");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.i = (m2) objA;
        C4203d c4203d = new C4203d(this);
        this.j = c4203d;
        E.A(p0.j(this), c4203d, null, new b(this, null), 2);
    }

    public static final void A(e eVar, List list) {
        Object value;
        s0 s0Var = eVar.g;
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, new p(eVar.B(), 28, list)));
    }

    public final boolean B() {
        Boolean bool = (Boolean) this.b.a("isPrivacySettingsPublic");
        if (bool != null) {
            return bool.booleanValue();
        }
        return true;
    }

    public final void C(h event) {
        String strA;
        Object next;
        Object value;
        Object value2;
        Object value3;
        Intrinsics.checkNotNullParameter(event, "event");
        boolean zB = Intrinsics.b(event, com.quizlet.features.universaluploadflow.flashcards.data.b.a);
        d0 d0Var = this.h;
        if (zB) {
            d0Var.h(i.a);
            return;
        }
        if (Intrinsics.b(event, com.quizlet.features.universaluploadflow.flashcards.data.c.a)) {
            d0Var.h(j.a);
            return;
        }
        boolean zB2 = Intrinsics.b(event, f.a);
        s0 s0Var = this.g;
        if (zB2) {
            this.b.c(Boolean.FALSE, "isPrivacySettingsPublic");
            Object value4 = s0Var.getValue();
            p pVar = value4 instanceof p ? (p) value4 : null;
            if (pVar != null) {
                do {
                    value3 = s0Var.getValue();
                } while (!s0Var.k(value3, p.b(pVar, null, 29)));
                return;
            }
            return;
        }
        boolean z = event instanceof com.quizlet.features.universaluploadflow.flashcards.data.e;
        C4203d c4203d = this.j;
        com.quizlet.features.universaluploadflow.logging.b bVar = this.e;
        if (z) {
            bVar.b();
            bVar.f();
            com.quizlet.features.universaluploadflow.logging.b.d(this.e, B(), EnumC4483g0.FLASHCARD_SET.a(), null, null, 12);
            Object value5 = s0Var.getValue();
            Intrinsics.e(value5, "null cannot be cast to non-null type com.quizlet.features.universaluploadflow.flashcards.data.UniversalUploadFlowFlashcardsUiState.Content");
            this.k = (p) value5;
            do {
                value2 = s0Var.getValue();
            } while (!s0Var.k(value2, new q(this.i)));
            E.A(p0.j(this), c4203d, null, new c(this, null), 2);
            return;
        }
        if (!(event instanceof com.quizlet.features.universaluploadflow.flashcards.data.d)) {
            if (!(event instanceof g)) {
                throw new NoWhenBranchMatchedException();
            }
            String str = ((g) event).a;
            y0 y0Var = this.l;
            if (y0Var != null) {
                y0Var.j(null);
            }
            this.l = E.A(p0.j(this), c4203d, null, new d(this, str, null), 2);
            return;
        }
        long j = ((com.quizlet.features.universaluploadflow.flashcards.data.d) event).a;
        bVar.getClass();
        UniversalUploadFlowEventLog.Companion companion = UniversalUploadFlowEventLog.b;
        m2 m2Var = bVar.b;
        EnumC4503n enumC4503nD = AbstractC3442d4.d(m2Var);
        Intrinsics.checkNotNullParameter(m2Var, "<this>");
        int iOrdinal = m2Var.ordinal();
        if (iOrdinal == 0 || iOrdinal == 1) {
            strA = EnumC4471c0.FLASHCARD_SET_DOCUMENT_SELECTED.a();
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            strA = "flashcard_set_document_selected";
        }
        m mVar = new m(20, j);
        companion.getClass();
        bVar.a(UniversalUploadFlowEventLog.Companion.a(enumC4503nD, strA, mVar));
        Object value6 = s0Var.getValue();
        p pVar2 = value6 instanceof p ? (p) value6 : null;
        if (pVar2 != null) {
            List<com.quizlet.features.universaluploadflow.flashcards.data.a> list = pVar2.a;
            Iterator it2 = list.iterator();
            while (true) {
                if (it2.hasNext()) {
                    next = it2.next();
                    if (((com.quizlet.features.universaluploadflow.flashcards.data.a) next).a.a == j) {
                        break;
                    }
                } else {
                    next = null;
                    break;
                }
            }
            com.quizlet.features.universaluploadflow.flashcards.data.a aVar = (com.quizlet.features.universaluploadflow.flashcards.data.a) next;
            if (Intrinsics.b(aVar != null ? Boolean.valueOf(aVar.c) : null, Boolean.TRUE) && B()) {
                d0Var.h(n.a);
                return;
            }
            ArrayList arrayList = new ArrayList(C.q(list, 10));
            for (com.quizlet.features.universaluploadflow.flashcards.data.a aVar2 : list) {
                com.quizlet.ui.models.content.listitem.d metadata = aVar2.a;
                if (metadata.a == j) {
                    boolean z2 = !aVar2.d;
                    Intrinsics.checkNotNullParameter(metadata, "metadata");
                    aVar2 = new com.quizlet.features.universaluploadflow.flashcards.data.a(metadata, aVar2.b, aVar2.c, z2);
                }
                arrayList.add(aVar2);
            }
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, p.b(pVar2, arrayList, 30)));
        }
    }
}
