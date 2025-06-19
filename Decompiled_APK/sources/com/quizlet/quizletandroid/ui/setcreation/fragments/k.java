package com.quizlet.quizletandroid.ui.setcreation.fragments;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;
import androidx.fragment.app.AbstractC1136h0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.setcreation.views.OcrCardView;
import com.quizlet.scandocument.model.A;
import com.quizlet.scandocument.model.EnumC4781a;
import com.quizlet.scandocument.model.q;
import com.quizlet.scandocument.model.r;
import com.quizlet.scandocument.model.s;
import com.quizlet.scandocument.model.t;
import com.quizlet.scandocument.model.u;
import com.quizlet.scandocument.model.v;
import com.quizlet.scandocument.model.w;
import com.quizlet.scandocument.model.x;
import com.quizlet.scandocument.model.y;
import com.quizlet.scandocument.model.z;
import com.quizlet.scandocument.ui.OcrDocumentView;
import com.quizlet.scandocument.ui.OcrToolbarView;
import com.quizlet.uicommon.ui.common.dialogs.e;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import java.util.ArrayList;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlin.text.StringsKt__StringsKt;

/* loaded from: classes3.dex */
public final /* synthetic */ class k implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ScanDocumentFragment b;

    public /* synthetic */ k(ScanDocumentFragment scanDocumentFragment, int i) {
        this.a = i;
        this.b = scanDocumentFragment;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                EnumC4781a inputMethod = (EnumC4781a) obj;
                ScanDocumentFragment scanDocumentFragment = this.b;
                OcrCardView ocrCardViewV = scanDocumentFragment.V();
                Intrinsics.d(inputMethod);
                ocrCardViewV.getClass();
                Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                int iOrdinal = inputMethod.ordinal();
                QFormField qFormField = ocrCardViewV.b;
                QFormField qFormField2 = ocrCardViewV.a;
                if (iOrdinal == 0) {
                    com.bumptech.glide.c.D(qFormField2.getEditText(), false);
                    com.bumptech.glide.c.D(qFormField.getEditText(), false);
                } else {
                    if (iOrdinal != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    com.bumptech.glide.c.D(qFormField2.getEditText(), true);
                    com.bumptech.glide.c.D(qFormField.getEditText(), true);
                }
                int iOrdinal2 = inputMethod.ordinal();
                if (iOrdinal2 == 0) {
                    if (scanDocumentFragment.e0().q instanceof com.quizlet.scandocument.model.k) {
                        OcrDocumentView ocrDocumentViewD0 = scanDocumentFragment.d0();
                        View view = ocrDocumentViewD0.u;
                        view.setVisibility(0);
                        ocrDocumentViewD0.q.setVisibility(8);
                        ocrDocumentViewD0.s.setVisibility(8);
                        view.setVisibility(0);
                    } else {
                        OcrDocumentView ocrDocumentViewD02 = scanDocumentFragment.d0();
                        ocrDocumentViewD02.getClass();
                        Intrinsics.checkNotNullParameter(inputMethod, "inputMethod");
                        int iOrdinal3 = inputMethod.ordinal();
                        if (iOrdinal3 == 0) {
                            ocrDocumentViewD02.p();
                        } else {
                            if (iOrdinal3 != 1) {
                                throw new NoWhenBranchMatchedException();
                            }
                            ocrDocumentViewD02.q.setVisibility(8);
                            ocrDocumentViewD02.u.setVisibility(8);
                        }
                    }
                    com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE0 = scanDocumentFragment.e0();
                    EditText editText = scanDocumentFragment.o;
                    if (editText == null) {
                        Intrinsics.m("focusedView");
                        throw null;
                    }
                    String flattenedWords = StringsKt.g0(editText.getText().toString()).toString();
                    hVarE0.getClass();
                    Intrinsics.checkNotNullParameter(flattenedWords, "flattenedWords");
                    if (!StringsKt.O(flattenedWords)) {
                        ArrayList arrayList = hVarE0.o;
                        arrayList.clear();
                        arrayList.addAll(StringsKt__StringsKt.split$default(flattenedWords, new String[]{" "}, false, 0, 6, null));
                    }
                } else {
                    if (iOrdinal2 != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    OcrDocumentView ocrDocumentViewD03 = scanDocumentFragment.d0();
                    ocrDocumentViewD03.q.setVisibility(8);
                    ocrDocumentViewD03.u.setVisibility(8);
                }
                return Unit.a;
            case 1:
                ScanDocumentFragment scanDocumentFragment2 = this.b;
                Uri uri = (Uri) obj;
                if (uri != null) {
                    try {
                        Context contextRequireContext = scanDocumentFragment2.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        com.quizlet.quizletandroid.ui.common.images.capture.a aVar = scanDocumentFragment2.k;
                        if (aVar == null) {
                            Intrinsics.m("imageCache");
                            throw null;
                        }
                        scanDocumentFragment2.e0().E(com.facebook.appevents.g.c(contextRequireContext, aVar, uri, false));
                        scanDocumentFragment2.d0().getOcrImageView().a();
                        OcrToolbarView ocrToolbarViewC0 = scanDocumentFragment2.c0();
                        ocrToolbarViewC0.getClass();
                        com.quizlet.scandocument.model.b bVar = com.quizlet.scandocument.model.b.a;
                        ocrToolbarViewC0.q = bVar;
                        ocrToolbarViewC0.v.b(bVar);
                    } catch (Exception e) {
                        scanDocumentFragment2.f0(R.string.scanning_error_dialog_title, R.string.scanning_error_dialog_generic_error_message);
                        timber.log.c.a.q(e, "Fail to handle image on ScanDocumentFragment", new Object[0]);
                    }
                }
                return Unit.a;
            case 2:
                String title = (String) obj;
                Intrinsics.checkNotNullParameter(title, "title");
                this.b.e0().F(title);
                return Unit.a;
            case 3:
                com.quizlet.scandocument.model.b newInteractionMode = (com.quizlet.scandocument.model.b) obj;
                OcrDocumentView ocrDocumentViewD04 = this.b.d0();
                Intrinsics.d(newInteractionMode);
                ocrDocumentViewD04.getClass();
                Intrinsics.checkNotNullParameter(newInteractionMode, "newInteractionMode");
                ocrDocumentViewD04.v.setInteractionMode(newInteractionMode);
                return Unit.a;
            case 4:
                Integer num = (Integer) obj;
                ScanDocumentFragment scanDocumentFragment3 = this.b;
                scanDocumentFragment3.requireActivity().setTitle(scanDocumentFragment3.getString(R.string.scan_document_activity_title, num, num));
                return Unit.a;
            case 5:
                q newState = (q) obj;
                boolean z = newState instanceof com.quizlet.scandocument.model.m;
                ScanDocumentFragment scanDocumentFragment4 = this.b;
                if (z) {
                    if (!(scanDocumentFragment4.e0().q instanceof com.quizlet.scandocument.model.k)) {
                        OcrDocumentView ocrDocumentViewD05 = scanDocumentFragment4.d0();
                        com.quizlet.scandocument.model.p newState2 = com.quizlet.scandocument.model.p.a;
                        ocrDocumentViewD05.q(newState2);
                        OcrToolbarView ocrToolbarViewC02 = scanDocumentFragment4.c0();
                        ocrToolbarViewC02.getClass();
                        Intrinsics.checkNotNullParameter(newState2, "newState");
                        ocrToolbarViewC02.C = newState2;
                        ocrToolbarViewC02.r();
                    }
                    com.quizlet.scandocument.model.m mVar = (com.quizlet.scandocument.model.m) newState;
                    scanDocumentFragment4.f0(mVar.a, mVar.b);
                } else {
                    OcrDocumentView ocrDocumentViewD06 = scanDocumentFragment4.d0();
                    Intrinsics.d(newState);
                    ocrDocumentViewD06.q(newState);
                    OcrToolbarView ocrToolbarViewC03 = scanDocumentFragment4.c0();
                    ocrToolbarViewC03.getClass();
                    Intrinsics.checkNotNullParameter(newState, "newState");
                    ocrToolbarViewC03.C = newState;
                    ocrToolbarViewC03.r();
                }
                return Unit.a;
            case 6:
                com.quizlet.scandocument.model.g gVar = (com.quizlet.scandocument.model.g) obj;
                boolean z2 = gVar instanceof com.quizlet.scandocument.model.f;
                ScanDocumentFragment scanDocumentFragment5 = this.b;
                if (z2) {
                    OcrToolbarView ocrToolbarViewC04 = scanDocumentFragment5.c0();
                    String term = scanDocumentFragment5.X();
                    String definition = scanDocumentFragment5.W();
                    ocrToolbarViewC04.getClass();
                    Intrinsics.checkNotNullParameter(term, "term");
                    Intrinsics.checkNotNullParameter(definition, "definition");
                    ocrToolbarViewC04.w.b(Boolean.valueOf(term.length() > 0 && definition.length() > 0));
                    OcrCardView ocrCardViewV2 = scanDocumentFragment5.V();
                    EditText editText2 = scanDocumentFragment5.o;
                    if (editText2 == null) {
                        Intrinsics.m("focusedView");
                        throw null;
                    }
                    ocrCardViewV2.a(editText2, new l(scanDocumentFragment5, 0));
                } else {
                    if (!(gVar instanceof com.quizlet.scandocument.model.e)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    scanDocumentFragment5.e0().I(((com.quizlet.scandocument.model.e) gVar).a);
                    scanDocumentFragment5.d0().getOcrImageView().a();
                }
                return Unit.a;
            case 7:
                A a = (A) obj;
                boolean z3 = a instanceof t;
                ScanDocumentFragment scanDocumentFragment6 = this.b;
                if (z3) {
                    scanDocumentFragment6.b0().setVisibility(0);
                } else if (a instanceof y) {
                    y yVar = (y) a;
                    com.quizlet.quizletandroid.ui.setcreation.tracking.c cVarY = scanDocumentFragment6.Y();
                    long j = yVar.a;
                    AndroidEventLog.b.getClass();
                    AndroidEventLog androidEventLogA = AndroidEventLog.Companion.a(1, j, yVar.b, "ocr_set_published", null);
                    androidEventLogA.setSize(Integer.valueOf(yVar.c));
                    cVarY.a.l(androidEventLogA);
                    scanDocumentFragment6.b0().setVisibility(8);
                    com.quizlet.features.setpage.e eVar = SetPageActivity.h1;
                    Context contextRequireContext2 = scanDocumentFragment6.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                    long id = scanDocumentFragment6.e0().D().getId();
                    DBStudySet dBStudySet = (DBStudySet) scanDocumentFragment6.e0().c.i;
                    Intent intentA = eVar.a(contextRequireContext2, id, (dBStudySet != null ? dBStudySet.getId() : 0L) <= 0);
                    intentA.addFlags(67108864);
                    scanDocumentFragment6.startActivity(intentA);
                    scanDocumentFragment6.requireActivity().finish();
                } else if (a instanceof w) {
                    Context contextRequireContext3 = scanDocumentFragment6.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                    Intent intentA2 = D4.a(contextRequireContext3, null);
                    intentA2.setFlags(268468224);
                    scanDocumentFragment6.startActivity(intentA2);
                    scanDocumentFragment6.requireActivity().finish();
                } else if (a instanceof u) {
                    e.a aVar2 = new e.a(scanDocumentFragment6.getContext());
                    aVar2.b = false;
                    aVar2.f(R.string.too_few_terms_dialog_title);
                    aVar2.e = scanDocumentFragment6.getString(R.string.too_few_terms_dialog_message);
                    aVar2.e(R.string.got_it, new com.quizlet.infra.legacysyncengine.models.serializers.a(28));
                    aVar2.b().show();
                } else if (a instanceof s) {
                    e.a aVar3 = new e.a(scanDocumentFragment6.requireContext());
                    aVar3.c(R.string.current_term_invalid_dialog_message);
                    aVar3.e(R.string.OK, new m(scanDocumentFragment6, 0));
                    aVar3.d(R.string.continue_editing, new m(scanDocumentFragment6, 1));
                    aVar3.g();
                } else if (a instanceof z) {
                    com.quizlet.quizletandroid.ui.setcreation.dialogs.a aVar4 = new com.quizlet.quizletandroid.ui.setcreation.dialogs.a();
                    AbstractC1136h0 fragmentManager = scanDocumentFragment6.requireActivity().getSupportFragmentManager();
                    Intrinsics.checkNotNullExpressionValue(fragmentManager, "getSupportFragmentManager(...)");
                    String title2 = scanDocumentFragment6.e0().D().getTitle();
                    Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
                    Intrinsics.checkNotNullParameter("SetTitleDialog", "tag");
                    aVar4.O(fragmentManager, "SetTitleDialog");
                    aVar4.s = title2;
                    k listener = new k(scanDocumentFragment6, 2);
                    Intrinsics.checkNotNullParameter(listener, "listener");
                    aVar4.q = listener;
                } else if (a instanceof x) {
                    int i = ((x) a).a;
                    e.a aVar5 = new e.a(scanDocumentFragment6.getContext());
                    aVar5.b = false;
                    aVar5.e = scanDocumentFragment6.getString(i);
                    aVar5.e(R.string.OK, new m(scanDocumentFragment6, 4));
                    aVar5.b().show();
                } else if (a instanceof v) {
                    scanDocumentFragment6.b0().setVisibility(8);
                    Toast.makeText(scanDocumentFragment6.requireContext(), ((v) a).a.a(scanDocumentFragment6.requireContext()), 1).show();
                } else {
                    if (!(a instanceof r)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    scanDocumentFragment6.b0().setVisibility(8);
                    Toast.makeText(scanDocumentFragment6.requireContext(), ((r) a).a.getMessage(), 1).show();
                }
                return Unit.a;
            default:
                String str = (String) obj;
                ScanDocumentFragment scanDocumentFragment7 = this.b;
                EditText editText3 = scanDocumentFragment7.o;
                if (editText3 == null) {
                    Intrinsics.m("focusedView");
                    throw null;
                }
                editText3.setText(str);
                EditText editText4 = scanDocumentFragment7.o;
                if (editText4 != null) {
                    editText4.setSelection(str.length());
                    return Unit.a;
                }
                Intrinsics.m("focusedView");
                throw null;
        }
    }
}
