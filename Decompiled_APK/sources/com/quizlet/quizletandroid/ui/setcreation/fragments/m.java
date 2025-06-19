package com.quizlet.quizletandroid.ui.setcreation.fragments;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.ads.Zh;
import com.quizlet.quizletandroid.sessionhelpers.EditSessionLoggingHelperState;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetDetailsActivity;
import io.reactivex.rxjava3.subjects.r;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class m implements com.quizlet.uicommon.ui.common.dialogs.f {
    public final /* synthetic */ int a;
    public final /* synthetic */ ScanDocumentFragment b;

    public /* synthetic */ m(ScanDocumentFragment scanDocumentFragment, int i) {
        this.a = i;
        this.b = scanDocumentFragment;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.f
    public final void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i) throws Exception {
        ScanDocumentFragment scanDocumentFragment = this.b;
        switch (this.a) {
            case 0:
                eVar.dismiss();
                scanDocumentFragment.e0().B();
                scanDocumentFragment.e0().F(scanDocumentFragment.e0().D().getTitle());
                return;
            case 1:
                eVar.dismiss();
                scanDocumentFragment.e0().B();
                return;
            case 2:
                eVar.dismiss();
                scanDocumentFragment.d0().q(com.quizlet.scandocument.model.p.a);
                return;
            case 3:
                scanDocumentFragment.Y().a.z("ocr_error_try_again");
                eVar.dismiss();
                scanDocumentFragment.g0();
                return;
            case 4:
                eVar.dismiss();
                Context contextRequireContext = scanDocumentFragment.requireContext();
                com.quizlet.quizletandroid.sessionhelpers.a aVar = scanDocumentFragment.p;
                if (aVar == null) {
                    Intrinsics.m("editTracker");
                    throw null;
                }
                EditSessionLoggingHelperState editSessionLoggingHelperState = aVar.a;
                long id = scanDocumentFragment.e0().D().getId();
                int i2 = EditSetDetailsActivity.y;
                Intent intent = new Intent(contextRequireContext, (Class<?>) EditSetDetailsActivity.class);
                intent.putExtra("editSetActivityId", id);
                intent.putExtra("autoSuggest", true);
                intent.putExtra("editSessionTrackerKey", editSessionLoggingHelperState);
                scanDocumentFragment.startActivityForResult(intent, com.pubmatic.sdk.common.h.AD_ALREADY_SHOWN);
                return;
            default:
                Zh zh = scanDocumentFragment.e0().c;
                ((r) zh.o).i(new com.quizlet.quizletandroid.ui.setcreation.managers.m(zh, 0), io.reactivex.rxjava3.internal.functions.d.e);
                eVar.dismiss();
                return;
        }
    }
}
