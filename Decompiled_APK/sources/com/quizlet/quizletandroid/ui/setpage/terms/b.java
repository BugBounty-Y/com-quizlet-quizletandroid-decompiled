package com.quizlet.quizletandroid.ui.setpage.terms;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.camera.core.AbstractC0151c;
import androidx.fragment.app.AbstractC1136h0;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.ui.diagramming.DiagramOverviewActivity;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import com.quizlet.uicommon.ui.common.dialogs.ImageOverlayDialogFragment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements com.quizlet.quizletandroid.ui.common.adapter.e, com.quizlet.quizletandroid.ui.common.adapter.f, com.quizlet.quizletandroid.ui.common.adapter.g {
    public final /* synthetic */ TermListFragment a;

    public /* synthetic */ b(TermListFragment termListFragment) {
        this.a = termListFragment;
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.g
    public void b() {
        String str = TermListFragment.H;
        TermListFragment termListFragment = this.a;
        termListFragment.f.setItemAnimator(null);
        long jLongValue = ((Number) termListFragment.G.getValue()).longValue();
        com.quizlet.quizletandroid.ui.setpage.g gVar = new com.quizlet.quizletandroid.ui.setpage.g();
        Bundle bundle = new Bundle();
        bundle.putLong("setId", jLongValue);
        gVar.setArguments(bundle);
        gVar.setTargetFragment(termListFragment, 100);
        AbstractC1136h0 supportFragmentManager = termListFragment.requireActivity().getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "getSupportFragmentManager(...)");
        AbstractC0151c.d(gVar, supportFragmentManager, gVar.getTag());
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.f
    public void d(DiagramData diagramData) {
        String str = TermListFragment.H;
        int i = DiagramOverviewActivity.o1;
        Context context = this.a.requireContext();
        Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
        long setId = diagramData.getSetId();
        Intrinsics.checkNotNullParameter(context, "context");
        Intent intentB = AbstractC4178x.b(context, "context", context, DiagramOverviewActivity.class);
        intentB.putExtra("setId", setId);
        context.startActivity(intentB);
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.e
    public void e(String str) {
        String str2 = TermListFragment.H;
        TermListFragment termListFragment = this.a;
        if (!termListFragment.isAdded() || termListFragment.getFragmentManager() == null) {
            return;
        }
        String str3 = ImageOverlayDialogFragment.x;
        Intrinsics.d(str);
        AbstractC1136h0 abstractC1136h0RequireFragmentManager = termListFragment.requireFragmentManager();
        Intrinsics.checkNotNullExpressionValue(abstractC1136h0RequireFragmentManager, "requireFragmentManager(...)");
        com.quizlet.quizletandroid.managers.upgrade.a.i(str, abstractC1136h0RequireFragmentManager, null);
    }
}
