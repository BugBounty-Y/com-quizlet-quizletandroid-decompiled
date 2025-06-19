package com.braze.ui.inappmessage;

import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.text.Editable;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.widget.EditText;
import androidx.appcompat.widget.SwitchCompat;
import androidx.compose.foundation.lazy.grid.m;
import androidx.lifecycle.p0;
import com.braze.ui.inappmessage.factories.DefaultInAppMessageModalViewFactory;
import com.braze.ui.inappmessage.views.InAppMessageModalView;
import com.comscore.streaming.EventType;
import com.facebook.internal.S;
import com.google.android.gms.ads.internal.client.F0;
import com.google.android.gms.ads.nativead.NativeCustomFormatAd;
import com.google.android.gms.ads.s;
import com.google.android.material.datepicker.l;
import com.google.android.material.textfield.i;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.onetrust.otpublishers.headless.UI.fragment.ViewOnClickListenerC4064h;
import com.onetrust.otpublishers.headless.UI.fragment.u;
import com.onetrust.otpublishers.headless.UI.fragment.v;
import com.quizlet.ads.ui.activity.AdsActivity;
import com.quizlet.ads.ui.fragments.NativeAdFragment;
import com.quizlet.edgy.ui.fragment.EdgyAddCourseManuallyFragment;
import com.quizlet.edgy.ui.fragment.EdgyAddSchoolManuallyFragment;
import com.quizlet.edgy.ui.viewmodel.C4202c;
import com.quizlet.edgy.ui.viewmodel.C4204e;
import com.quizlet.edgy.ui.viewmodel.w;
import com.quizlet.explanations.feedback.ui.fragments.ExplanationsFeedbackFragment;
import com.quizlet.explanations.feedback.ui.fragments.ExplanationsFeedbackModalFragment;
import com.quizlet.explanations.feedback.ui.fragments.ThanksForReportingFragment;
import com.quizlet.explanations.solution.solutionwall.g;
import com.quizlet.features.setpage.progress.presentation.ui.SetPageProgressFragment;
import com.quizlet.features.setpage.r;
import com.quizlet.features.setpage.viewmodel.H;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.FullScreenOverlayActivity;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final /* synthetic */ class d implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Type inference failed for: r7v55, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.o] */
    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        Drawable trackDrawable;
        int color;
        s sVarA;
        Function1 function1B;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                DefaultInAppMessageViewWrapper.createClickListener$lambda$16((DefaultInAppMessageViewWrapper) obj, view);
                return;
            case 1:
                DefaultInAppMessageModalViewFactory.createInAppMessageView$lambda$2((DefaultInAppMessageModalViewFactory) obj, view);
                return;
            case 2:
                InAppMessageModalView.resetMessageMargins$lambda$1((InAppMessageModalView) obj, view);
                return;
            case 3:
                S this$0 = (S) obj;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                this$0.cancel();
                return;
            case 4:
                ((l) obj).P();
                throw null;
            case 5:
                com.google.android.material.textfield.d dVar = (com.google.android.material.textfield.d) obj;
                EditText editText = dVar.i;
                if (editText == null) {
                    return;
                }
                Editable text = editText.getText();
                if (text != null) {
                    text.clear();
                }
                dVar.q();
                return;
            case 6:
                ((i) obj).u();
                return;
            case 7:
                com.google.android.material.textfield.s sVar = (com.google.android.material.textfield.s) obj;
                EditText editText2 = sVar.f;
                if (editText2 == null) {
                    return;
                }
                int selectionEnd = editText2.getSelectionEnd();
                EditText editText3 = sVar.f;
                if (editText3 == null || !(editText3.getTransformationMethod() instanceof PasswordTransformationMethod)) {
                    sVar.f.setTransformationMethod(PasswordTransformationMethod.getInstance());
                } else {
                    sVar.f.setTransformationMethod(null);
                }
                if (selectionEnd >= 0) {
                    sVar.f.setSelection(selectionEnd);
                }
                sVar.q();
                return;
            case 8:
                ViewOnClickListenerC4064h viewOnClickListenerC4064h = (ViewOnClickListenerC4064h) obj;
                viewOnClickListenerC4064h.y.updateVendorConsent(OTVendorListMode.GENERAL, viewOnClickListenerC4064h.E, viewOnClickListenerC4064h.A.isChecked());
                if (viewOnClickListenerC4064h.A.isChecked()) {
                    viewOnClickListenerC4064h.Q(viewOnClickListenerC4064h.A);
                } else {
                    SwitchCompat switchCompat = viewOnClickListenerC4064h.A;
                    if (viewOnClickListenerC4064h.K != null) {
                        trackDrawable = switchCompat.getTrackDrawable();
                        color = Color.parseColor(viewOnClickListenerC4064h.K);
                    } else {
                        trackDrawable = switchCompat.getTrackDrawable();
                        color = viewOnClickListenerC4064h.x.getColor(R.color.light_greyOT);
                    }
                    trackDrawable.setTint(color);
                    switchCompat.getThumbDrawable().setTint(viewOnClickListenerC4064h.J != null ? Color.parseColor(viewOnClickListenerC4064h.J) : viewOnClickListenerC4064h.x.getColor(R.color.contentTextColorOT));
                }
                String strOptString = viewOnClickListenerC4064h.z.optString("VendorCustomId");
                m mVar = new m(15, 4);
                mVar.c = strOptString;
                mVar.b = viewOnClickListenerC4064h.A.isChecked() ? 1 : 0;
                mVar.e = OTVendorListMode.GENERAL;
                com.onetrust.otpublishers.headless.Internal.Event.a aVar = viewOnClickListenerC4064h.Z;
                if (aVar != null) {
                    aVar.a(mVar);
                    return;
                } else {
                    OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                    return;
                }
            case 9:
                ((u) obj).G();
                return;
            case 10:
                ((v) obj).G();
                return;
            case 11:
                String str = AdsActivity.u;
                ((AdsActivity) obj).finish();
                return;
            case 12:
                String str2 = NativeAdFragment.m;
                NativeCustomFormatAd nativeCustomFormatAd = (NativeCustomFormatAd) obj;
                com.google.android.gms.ads.m mediaContent = nativeCustomFormatAd.getMediaContent();
                if (mediaContent == null || (sVarA = ((F0) mediaContent).a()) == null || !sVarA.a()) {
                    nativeCustomFormatAd.performClick("CallToAction");
                    return;
                } else {
                    nativeCustomFormatAd.performClick("Calltoaction");
                    return;
                }
            case 13:
                String str3 = EdgyAddCourseManuallyFragment.m;
                EdgyAddCourseManuallyFragment edgyAddCourseManuallyFragment = (EdgyAddCourseManuallyFragment) obj;
                String name = String.valueOf(((com.quizlet.edgy.databinding.a) edgyAddCourseManuallyFragment.J()).d.getText());
                String code = String.valueOf(((com.quizlet.edgy.databinding.a) edgyAddCourseManuallyFragment.J()).c.getText());
                C4204e c4204e = (C4204e) edgyAddCourseManuallyFragment.k.getValue();
                c4204e.getClass();
                Intrinsics.checkNotNullParameter(name, "name");
                Intrinsics.checkNotNullParameter(code, "code");
                E.A(p0.j(c4204e), c4204e.f, null, new C4202c(c4204e, name, code, null), 2);
                return;
            case 14:
                String str4 = EdgyAddSchoolManuallyFragment.o;
                EdgyAddSchoolManuallyFragment edgyAddSchoolManuallyFragment = (EdgyAddSchoolManuallyFragment) obj;
                String school = String.valueOf(((com.quizlet.edgy.databinding.c) edgyAddSchoolManuallyFragment.J()).e.getText());
                String city = String.valueOf(((com.quizlet.edgy.databinding.c) edgyAddSchoolManuallyFragment.J()).c.getText());
                w wVarU = edgyAddSchoolManuallyFragment.U();
                wVarU.getClass();
                Intrinsics.checkNotNullParameter(school, "school");
                Intrinsics.checkNotNullParameter(city, "city");
                E.A(p0.j(wVarU), wVarU.k, null, new com.quizlet.edgy.ui.viewmodel.v(wVarU, school, city, null), 2);
                return;
            case 15:
                ((com.quizlet.edgy.ui.recyclerview.viewholder.a) obj).d.invoke();
                return;
            case 16:
                ((com.quizlet.edgy.ui.recyclerview.viewholder.b) obj).d.invoke();
                return;
            case 17:
                ExplanationsFeedbackModalFragment explanationsFeedbackModalFragment = ((ExplanationsFeedbackFragment) obj).k;
                if (explanationsFeedbackModalFragment != null) {
                    explanationsFeedbackModalFragment.H(false, false);
                    return;
                }
                return;
            case 18:
                ((com.quizlet.explanations.feedback.viewmodel.a) ((ThanksForReportingFragment) obj).j.getValue()).g.j(Unit.a);
                return;
            case 19:
                ((com.quizlet.explanations.solution.recyclerview.revealbutton.b) obj).a.invoke();
                return;
            case 20:
                ((g) obj).a().invoke();
                return;
            case 21:
                com.quizlet.explanations.textbook.chaptermenu.recyclerview.d dVar2 = (com.quizlet.explanations.textbook.chaptermenu.recyclerview.d) obj;
                function1B = dVar2.e ? dVar2.f : null;
                if (function1B != null) {
                    function1B.invoke(dVar2.d);
                    return;
                }
                return;
            case EventType.WINDOW_STATE /* 22 */:
                com.quizlet.explanations.textbook.chaptermenu.recyclerview.c cVar = (com.quizlet.explanations.textbook.chaptermenu.recyclerview.c) obj;
                function1B = cVar.a() ? cVar.b() : null;
                if (function1B != null) {
                    ((com.quizlet.explanations.solution.fragments.b) function1B).invoke(cVar.b);
                    return;
                }
                return;
            case EventType.AUDIO /* 23 */:
                com.quizlet.explanations.textbook.chaptermenu.recyclerview.i iVar = (com.quizlet.explanations.textbook.chaptermenu.recyclerview.i) obj;
                function1B = iVar.e ? iVar.f : null;
                if (function1B != null) {
                    function1B.invoke(iVar.d);
                    return;
                }
                return;
            case EventType.VIDEO /* 24 */:
                com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.b bVar = (com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.b) obj;
                bVar.c.invoke(bVar.a);
                return;
            case EventType.SUBS /* 25 */:
                com.quizlet.explanations.textbook.tableofcontents.recyclerview.d dVar3 = (com.quizlet.explanations.textbook.tableofcontents.recyclerview.d) obj;
                function1B = dVar3.d ? dVar3.f : null;
                if (function1B != null) {
                    function1B.invoke(dVar3.e);
                    return;
                }
                return;
            case EventType.CDN /* 26 */:
                P pR = ((r) obj).R();
                pR.f.A("set_page_study_this_set_clicked");
                pR.c1.j(new com.quizlet.features.setpage.screenstates.l(pR.K1));
                E.A(p0.j(pR), pR.J1, null, new H(pR, null), 2);
                return;
            case 27:
                Function0 function0 = ((com.quizlet.features.infra.snackbar.l) obj).e;
                if (function0 != null) {
                    function0.invoke();
                    return;
                }
                return;
            case 28:
                SetPageProgressFragment.T((SetPageProgressFragment) obj, view);
                return;
            default:
                String str5 = FullScreenOverlayActivity.m;
                ((FullScreenOverlayActivity) obj).finish();
                return;
        }
    }
}
