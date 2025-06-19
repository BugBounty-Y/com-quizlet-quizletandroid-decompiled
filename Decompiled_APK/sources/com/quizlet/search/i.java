package com.quizlet.search;

import android.content.Context;
import androidx.fragment.app.AbstractC1136h0;
import androidx.glance.appwidget.protobuf.Z;
import com.facebook.internal.K;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.dialogs.QAlertDialogFragment;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ TermSearchFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(TermSearchFragment termSearchFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = termSearchFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        i iVar = new i(this.k, hVar);
        iVar.j = obj;
        return iVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((com.quizlet.search.data.term.d) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.search.data.term.d dVar = (com.quizlet.search.data.term.d) this.j;
        boolean z = dVar instanceof com.quizlet.search.data.term.c;
        TermSearchFragment termSearchFragment = this.k;
        if (z) {
            if (termSearchFragment.J == null) {
                Intrinsics.m("navigationManager");
                throw null;
            }
            Context context = termSearchFragment.requireContext();
            Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
            long j = ((com.quizlet.search.data.term.c) dVar).a;
            Intrinsics.checkNotNullParameter(context, "context");
            com.quizlet.features.setpage.e eVar = SetPageActivity.h1;
            context.startActivity(com.quizlet.features.setpage.e.c(28, j, context));
            termSearchFragment.H(false, false);
        } else if (Intrinsics.b(dVar, com.quizlet.search.data.term.b.b)) {
            AbstractC1136h0 parentFragmentManager = termSearchFragment.getParentFragmentManager();
            String str = QAlertDialogFragment.t;
            if (parentFragmentManager.E(str) == null) {
                Context contextRequireContext = termSearchFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                com.quizlet.explanations.questiondetail.ui.d dVar2 = new com.quizlet.explanations.questiondetail.ui.d(termSearchFragment, 5);
                K k = new K(termSearchFragment, 7);
                String message = contextRequireContext.getString(R.string.client_error_net_exception);
                Intrinsics.checkNotNullExpressionValue(message, "getString(...)");
                Intrinsics.checkNotNullParameter(message, "message");
                String text = contextRequireContext.getString(R.string.OK);
                Intrinsics.checkNotNullExpressionValue(text, "getString(...)");
                Intrinsics.checkNotNullParameter(text, "text");
                com.quizlet.uicommon.ui.common.dialogs.h.a(new com.quizlet.uicommon.ui.common.dialogs.i(new QAlertDialogFragment.DialogData(message, null, text, null, true, null), dVar2, null, k)).O(termSearchFragment.getParentFragmentManager(), str);
            }
        } else {
            if (!Intrinsics.b(dVar, com.quizlet.search.data.term.b.a)) {
                throw new NoWhenBranchMatchedException();
            }
            termSearchFragment.H(false, false);
        }
        return Unit.a;
    }
}
