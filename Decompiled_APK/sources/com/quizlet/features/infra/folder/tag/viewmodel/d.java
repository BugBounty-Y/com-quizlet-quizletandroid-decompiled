package com.quizlet.features.infra.folder.tag.viewmodel;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.A6;
import com.quizlet.data.model.EnumC4159q0;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.features.infra.folder.tag.screenstates.f;
import com.quizlet.features.infra.folder.tag.screenstates.h;
import com.quizlet.features.infra.folder.tag.screenstates.i;
import com.quizlet.features.infra.folder.tag.screenstates.j;
import com.quizlet.features.infra.folder.tag.screenstates.k;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.collections.b0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.collections.immutable.e;
import kotlinx.collections.immutable.implementations.immutableList.g;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class d extends w0 implements a {
    public final com.quizlet.data.interactor.course.a b;
    public final com.quizlet.data.interactor.school.b c;
    public final com.quizlet.data.repository.explanations.myexplanations.a d;
    public final FolderLogger e;
    public long f;
    public final ArrayList g;
    public e h;
    public final s0 i;
    public final d0 j;

    public d(com.quizlet.data.interactor.course.a createSubfoldersUseCase, com.quizlet.data.interactor.school.b getSubfolderNameRecommendationsUseCase, com.quizlet.data.repository.explanations.myexplanations.a validateTagUseCase, FolderLogger folderLogger) {
        Intrinsics.checkNotNullParameter(createSubfoldersUseCase, "createSubfoldersUseCase");
        Intrinsics.checkNotNullParameter(getSubfolderNameRecommendationsUseCase, "getSubfolderNameRecommendationsUseCase");
        Intrinsics.checkNotNullParameter(validateTagUseCase, "validateTagUseCase");
        Intrinsics.checkNotNullParameter(folderLogger, "folderLogger");
        this.b = createSubfoldersUseCase;
        this.c = getSubfolderNameRecommendationsUseCase;
        this.d = validateTagUseCase;
        this.e = folderLogger;
        this.g = new ArrayList();
        this.h = g.c;
        this.i = e0.c(new k(null, null, 15));
        this.j = e0.b(0, 0, null, 7);
    }

    public final void A(j newTagModalEvent) {
        Object value;
        Object value2;
        Object value3;
        Object value4;
        Object value5;
        Intrinsics.checkNotNullParameter(newTagModalEvent, "newTagModalEvent");
        boolean z = newTagModalEvent instanceof com.quizlet.features.infra.folder.tag.screenstates.d;
        ArrayList arrayList = this.g;
        com.quizlet.data.repository.explanations.myexplanations.a aVar = this.d;
        FolderLogger folderLogger = this.e;
        s0 s0Var = this.i;
        if (z) {
            com.quizlet.features.infra.folder.tag.screenstates.d dVar = (com.quizlet.features.infra.folder.tag.screenstates.d) newTagModalEvent;
            String str = dVar.a;
            EnumC4159q0 enumC4159q0A = A6.a(aVar, str, b0.f(CollectionsKt.A0(this.h), CollectionsKt.A0(arrayList)));
            if (!StringsKt.O(str) && enumC4159q0A == EnumC4159q0.a) {
                arrayList.add(StringsKt.g0(str).toString());
            }
            do {
                value5 = s0Var.getValue();
            } while (!s0Var.k(value5, k.a((k) value5, AbstractC3409x1.i(arrayList), enumC4159q0A, false, null, 12)));
            if (dVar.b) {
                folderLogger.e(this.f, str);
                return;
            } else {
                folderLogger.d(this.f, str);
                return;
            }
        }
        if (newTagModalEvent instanceof i) {
            List list = ((i) newTagModalEvent).a;
            do {
                value4 = s0Var.getValue();
            } while (!s0Var.k(value4, k.a((k) value4, null, null, true, null, 11)));
            E.A(p0.j(this), null, null, new c(this, list, null), 3);
            return;
        }
        if (newTagModalEvent instanceof com.quizlet.features.infra.folder.tag.screenstates.e) {
            com.quizlet.features.infra.folder.tag.screenstates.e eVar = (com.quizlet.features.infra.folder.tag.screenstates.e) newTagModalEvent;
            long j = eVar.a;
            List list2 = eVar.b;
            this.f = j;
            ArrayList arrayList2 = new ArrayList();
            for (Object obj : list2) {
                if (((String) obj).length() != 0) {
                    arrayList2.add(obj);
                }
            }
            this.h = AbstractC3409x1.k(arrayList2);
            E.A(p0.j(this), null, null, new b(this, null), 3);
            folderLogger.I(j);
            return;
        }
        if (newTagModalEvent instanceof com.quizlet.features.infra.folder.tag.screenstates.g) {
            arrayList.remove(((com.quizlet.features.infra.folder.tag.screenstates.g) newTagModalEvent).a);
            do {
                value3 = s0Var.getValue();
            } while (!s0Var.k(value3, k.a((k) value3, AbstractC3409x1.i(arrayList), null, false, null, 14)));
        } else if (newTagModalEvent instanceof h) {
            EnumC4159q0 enumC4159q0L = aVar.l(((h) newTagModalEvent).a);
            do {
                value2 = s0Var.getValue();
            } while (!s0Var.k(value2, k.a((k) value2, null, enumC4159q0L, false, null, 13)));
        } else {
            if (!Intrinsics.b(newTagModalEvent, f.a)) {
                throw new NoWhenBranchMatchedException();
            }
            arrayList.clear();
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, new k(null, null, 15)));
            folderLogger.k(this.f);
        }
    }
}
