package com.quizlet.features.notes.detail.composables.magicnotesdetail;

import androidx.compose.animation.C0293u;
import androidx.compose.foundation.layout.z0;
import com.google.android.gms.internal.mlkit_vision_camera.Y2;
import com.quizlet.data.model.EssayInfo;
import com.quizlet.data.model.FlashcardsInfo;
import com.quizlet.data.model.OutlineMarkdownInfo;
import com.quizlet.features.folders.composables.C4256l;
import com.quizlet.quizletandroid.ui.library.C4680z;
import java.util.ArrayList;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class t implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    public /* synthetic */ t(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, Object obj6, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
        this.f = obj5;
        this.g = obj6;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -778742230, new com.quizlet.features.blocks.ui.d((com.quizlet.features.notes.detail.states.g) this.b, (OutlineMarkdownInfo) this.c, (Function1) this.d, (FlashcardsInfo) this.e, (EssayInfo) this.f, (z0) this.g, 1)), 3);
                return Unit.a;
            case 1:
                androidx.compose.foundation.lazy.g LazyColumn2 = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn2, "$this$LazyColumn");
                if (((com.quizlet.features.questiontypes.mcq.data.d) this.b).e) {
                    androidx.compose.foundation.lazy.g.p(LazyColumn2, null, com.quizlet.features.questiontypes.mcq.ui.b.a, 3);
                }
                com.quizlet.features.questiontypes.mcq.a mcqViewModel = (com.quizlet.features.questiontypes.mcq.a) this.d;
                Y2 answerState = (Y2) this.c;
                androidx.compose.foundation.lazy.g.p(LazyColumn2, null, new androidx.compose.runtime.internal.d(true, 1487591563, new C4256l(mcqViewModel, answerState, (com.quizlet.features.questiontypes.data.b) this.e, (com.quizlet.assembly.compose.modals.x) this.f, (com.quizlet.features.questiontypes.data.d) this.g, 3)), 3);
                Intrinsics.checkNotNullParameter(LazyColumn2, "<this>");
                Intrinsics.checkNotNullParameter(answerState, "answerState");
                Intrinsics.checkNotNullParameter(mcqViewModel, "mcqViewModel");
                if (answerState instanceof com.quizlet.features.questiontypes.mcq.data.c) {
                    com.quizlet.features.questiontypes.mcq.data.c answers = (com.quizlet.features.questiontypes.mcq.data.c) answerState;
                    com.quizlet.features.folders.composables.J onClick = new com.quizlet.features.folders.composables.J(mcqViewModel, 12);
                    Intrinsics.checkNotNullParameter(LazyColumn2, "<this>");
                    Intrinsics.checkNotNullParameter(answers, "answers");
                    Intrinsics.checkNotNullParameter(onClick, "onClick");
                    androidx.compose.foundation.lazy.g.p(LazyColumn2, null, new androidx.compose.runtime.internal.d(true, -1486087701, new com.quizlet.baseui.base.d(answers, 11)), 3);
                    ArrayList arrayList = answers.a;
                    LazyColumn2.q(arrayList.size(), null, new C0293u(7, arrayList), new androidx.compose.runtime.internal.d(true, -1091073711, new com.quizlet.features.practicetest.common.composables.k(arrayList, onClick, 1)));
                } else {
                    if (!(answerState instanceof com.quizlet.features.questiontypes.mcq.data.b)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    androidx.compose.foundation.lazy.g.p(LazyColumn2, null, new androidx.compose.runtime.internal.d(true, 1837542945, new com.quizlet.baseui.base.d(answerState, 10)), 3);
                    androidx.compose.foundation.lazy.g.p(LazyColumn2, null, new androidx.compose.runtime.internal.d(true, -1983896246, new com.quizlet.features.questiontypes.mcq.ui.c(0, answerState, mcqViewModel)), 3);
                }
                return Unit.a;
            default:
                androidx.compose.foundation.lazy.grid.i LazyVerticalGrid = (androidx.compose.foundation.lazy.grid.i) obj;
                Intrinsics.checkNotNullParameter(LazyVerticalGrid, "$this$LazyVerticalGrid");
                androidx.navigation.compose.x xVar = new androidx.navigation.compose.x(23);
                kotlinx.collections.immutable.b bVar = (kotlinx.collections.immutable.b) this.b;
                LazyVerticalGrid.p(bVar.size(), new androidx.compose.ui.viewinterop.b(22, xVar, bVar), null, new com.quizlet.assembly.compose.menu.e(bVar, 14), new androidx.compose.runtime.internal.d(true, 1229287273, new C4680z(bVar, xVar, (androidx.compose.foundation.lazy.grid.A) this.c, (Function1) this.d, (Function1) this.e, (Function1) this.f, (Function1) this.g)));
                return Unit.a;
        }
    }
}
