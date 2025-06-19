package com.google.android.material.textfield;

import android.view.View;
import android.widget.EditText;
import com.quizlet.edgy.ui.fragment.EdgyAddSchoolAndCoursesFragment;
import com.quizlet.edgy.ui.viewmodel.M;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.login.BaseSignupFragment;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.setcreation.fragments.ScanDocumentFragment;
import com.quizlet.quizletandroid.ui.setcreation.views.OcrCardView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements View.OnFocusChangeListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        int i = 1;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                d dVar = (d) obj;
                dVar.t(dVar.u());
                return;
            case 1:
                i iVar = (i) obj;
                iVar.l = z;
                iVar.q();
                if (z) {
                    return;
                }
                iVar.t(false);
                iVar.m = false;
                return;
            case 2:
                String str = EdgyAddSchoolAndCoursesFragment.u;
                if (z) {
                    M mU = ((EdgyAddSchoolAndCoursesFragment) obj).U();
                    mU.getClass();
                    mU.F(true);
                    return;
                }
                return;
            case 3:
                BaseSignupFragment baseSignupFragment = (BaseSignupFragment) obj;
                if (!baseSignupFragment.isAdded() || z) {
                    return;
                }
                if (baseSignupFragment.j == null) {
                    Intrinsics.m("emailUtil");
                    throw null;
                }
                if (com.quizlet.qutils.string.c.c(String.valueOf(baseSignupFragment.R().getText()))) {
                    return;
                }
                baseSignupFragment.R().setError(baseSignupFragment.getString(R.string.invalid_email));
                return;
            case 4:
                String str2 = EditSetFragment.J;
                ((EditSetFragment) obj).c0().j.j(Boolean.valueOf(z));
                return;
            case 5:
                Intrinsics.checkNotNullParameter(view, "view");
                if (z && (view instanceof EditText)) {
                    ScanDocumentFragment scanDocumentFragment = (ScanDocumentFragment) obj;
                    scanDocumentFragment.o = (EditText) view;
                    OcrCardView ocrCardViewV = scanDocumentFragment.V();
                    EditText editText = scanDocumentFragment.o;
                    if (editText == null) {
                        Intrinsics.m("focusedView");
                        throw null;
                    }
                    ocrCardViewV.a(editText, new com.quizlet.quizletandroid.ui.setcreation.fragments.l(scanDocumentFragment, i));
                    scanDocumentFragment.d0().getOcrImageView().a();
                    com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE0 = scanDocumentFragment.e0();
                    com.quizlet.scandocument.a aVar = hVarE0.e;
                    hVarE0.n = aVar.b.size();
                    aVar.b.clear();
                    hVarE0.o.clear();
                    return;
                }
                return;
            default:
                if (z) {
                    return;
                }
                ((com.quizlet.quizletandroid.ui.setcreation.viewholders.g) obj).g();
                return;
        }
    }
}
