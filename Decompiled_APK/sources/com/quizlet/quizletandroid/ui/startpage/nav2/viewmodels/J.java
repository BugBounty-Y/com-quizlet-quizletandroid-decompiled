package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.generated.enums.I1;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class J extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ L j;
    public final /* synthetic */ I1 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J(L l, I1 i1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = l;
        this.k = i1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new J(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((J) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        L l = this.j;
        com.quizlet.data.interactor.achievements.f fVar = l.j;
        I1 subjectCategoryType = this.k;
        String subjectCategory = subjectCategoryType.a();
        fVar.getClass();
        Intrinsics.checkNotNullParameter(subjectCategory, "subjectCategory");
        EventLoggerExt.c((EventLogger) fVar.b, new com.quizlet.features.notes.logging.c(subjectCategory, 25));
        l.p.h(new x(subjectCategoryType));
        com.quizlet.quizletandroid.ui.startpage.nav2.logging.a aVar2 = l.i;
        Intrinsics.checkNotNullParameter(aVar2, "<this>");
        Intrinsics.checkNotNullParameter(subjectCategoryType, "subjectCategoryType");
        int i = com.quizlet.quizletandroid.ui.startpage.nav2.logging.b.a[subjectCategoryType.ordinal()];
        if (i == 1) {
            aVar2.a("subject_click_art", "subjects");
        } else if (i == 2) {
            aVar2.a("subject_click_languages", "subjects");
        } else if (i == 3) {
            aVar2.a("subject_click_science", "subjects");
        } else if (i == 4) {
            aVar2.a("subject_click_social_science", "subjects");
        } else {
            if (i != 5) {
                throw new NoWhenBranchMatchedException();
            }
            aVar2.a("subject_click_math", "subjects");
        }
        return Unit.a;
    }
}
