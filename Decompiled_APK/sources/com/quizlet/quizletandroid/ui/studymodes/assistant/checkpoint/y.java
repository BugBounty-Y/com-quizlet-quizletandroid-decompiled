package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.os.Bundle;
import android.text.Html;
import android.view.View;
import androidx.compose.ui.text.C0995g;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.p0;
import androidx.recyclerview.widget.RecyclerView;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.I6;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.search.SearchEventsEventLog;
import com.quizlet.features.infra.legacyadapter.layoutmanager.CenterLayoutManager;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.match.data.AbstractC4367x;
import com.quizlet.features.match.data.C4359o;
import com.quizlet.features.match.data.C4364u;
import com.quizlet.features.match.data.C4365v;
import com.quizlet.features.match.data.C4366w;
import com.quizlet.features.match.data.D;
import com.quizlet.features.match.data.E;
import com.quizlet.features.match.data.F;
import com.quizlet.features.match.data.G;
import com.quizlet.features.match.data.J;
import com.quizlet.features.match.data.K;
import com.quizlet.features.match.data.L;
import com.quizlet.features.match.data.M;
import com.quizlet.features.match.data.N;
import com.quizlet.features.match.data.T;
import com.quizlet.features.match.data.W;
import com.quizlet.features.match.data.Z;
import com.quizlet.features.match.data.a0;
import com.quizlet.generated.enums.EnumC4466a1;
import com.quizlet.generated.enums.K1;
import com.quizlet.generated.enums.Q0;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QProgressBar;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.views.ShareSetButton;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.LearnSettingsGradingUpdateData;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.DiagramMatchGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.MatchEndGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.MatchGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.MatchStartGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.StandardMatchGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.challenge.ChallengeDialogFragment;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4761c;
import com.quizlet.quizletandroid.ui.usersettings.fragments.ChangeProfileImageFragment;
import com.quizlet.quizletandroid.ui.usersettings.fragments.CropImageFragment;
import com.quizlet.search.viewmodels.C4806l;
import java.util.ArrayList;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

/* loaded from: classes3.dex */
public final /* synthetic */ class y extends C4956o implements Function1 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ y(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        W w;
        DBStudySet dBStudySet;
        String strValueOf;
        Object value;
        Object value2;
        s0 s0Var;
        Object value3;
        EnumC4466a1 enumC4466a1;
        int iIndexOf = -1;
        final int i = 4;
        final int i2 = 1;
        final int i3 = 2;
        final int i4 = 3;
        final int i5 = 0;
        String str = null;
        switch (this.a) {
            case 0:
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.f p0 = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.f) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i) ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b) this.receiver)).E(p0);
                return Unit.a;
            case 1:
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.f p02 = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.f) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i) ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b) this.receiver)).E(p02);
                return Unit.a;
            case 2:
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.h p03 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.h) obj;
                Intrinsics.checkNotNullParameter(p03, "p0");
                ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i) ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a) this.receiver)).C(p03);
                return Unit.a;
            case 3:
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.h p04 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.h) obj;
                Intrinsics.checkNotNullParameter(p04, "p0");
                ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i) ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a) this.receiver)).C(p04);
                return Unit.a;
            case 4:
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.c event = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.c) obj;
                Intrinsics.checkNotNullParameter(event, "p0");
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.g gVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.g) ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.a) this.receiver);
                gVar.getClass();
                Intrinsics.checkNotNullParameter(event, "event");
                boolean zB = Intrinsics.b(event, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.b.a);
                d0 d0Var = gVar.i;
                if (zB) {
                    d0Var.h(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.e.a);
                } else {
                    if (!(event instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    LearnSettingsGradingUpdateData learnSettingsGradingUpdateData = ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.a) event).a;
                    com.quizlet.data.repository.course.membership.c cVar = gVar.f;
                    cVar.getClass();
                    com.quizlet.features.infra.basestudy.manager.f studyModeManager = gVar.j;
                    Intrinsics.checkNotNullParameter(studyModeManager, "studyModeManager");
                    Intrinsics.checkNotNullParameter(learnSettingsGradingUpdateData, "learnSettingsGradingUpdateData");
                    com.quizlet.features.infra.studysetting.managers.a aVarG = studyModeManager.g();
                    QuestionSettings questionSettingsC = aVarG.c();
                    QuestionSettings questionSettingsA = QuestionSettings.a(questionSettingsC, null, null, false, false, false, false, false, false, false, null, null, learnSettingsGradingUpdateData.b, learnSettingsGradingUpdateData.c, learnSettingsGradingUpdateData.a, false, false, 204799);
                    if (!questionSettingsA.equals(questionSettingsC)) {
                        if (questionSettingsA.o != questionSettingsC.o) {
                            ((EventLogger) cVar.c).q("android_learn_smart_grading_changed");
                        }
                        QuestionSettings questionSettingsG = ((com.quizlet.quizletandroid.managers.upgrade.a) cVar.a).g(questionSettingsA, questionSettingsC);
                        List list = studyModeManager.x.x;
                        aVarG.l(questionSettingsG);
                        ((com.quizlet.infra.legacysyncengine.net.f) cVar.b).b(list);
                    }
                    d0Var.h(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.d.a);
                }
                return Unit.a;
            case 5:
                C4359o p05 = (C4359o) obj;
                Intrinsics.checkNotNullParameter(p05, "p0");
                final MatchEndGameFragment matchEndGameFragment = (MatchEndGameFragment) this.receiver;
                String str2 = MatchEndGameFragment.p;
                com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g gVarV = matchEndGameFragment.V();
                N screen = N.c;
                gVarV.getClass();
                Intrinsics.checkNotNullParameter(screen, "screen");
                gVarV.l.o(screen);
                com.quizlet.qutils.string.f fVar = p05.a;
                QTextView matchFinishText = ((com.quizlet.quizletandroid.databinding.B) matchEndGameFragment.J()).e;
                Intrinsics.checkNotNullExpressionValue(matchFinishText, "matchFinishText");
                Context contextRequireContext = matchEndGameFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                matchFinishText.setText(AbstractC3053s1.e(p05.b, contextRequireContext));
                QTextView matchFinishText2 = ((com.quizlet.quizletandroid.databinding.B) matchEndGameFragment.J()).e;
                Intrinsics.checkNotNullExpressionValue(matchFinishText2, "matchFinishText");
                QTextView matchFinishText3 = ((com.quizlet.quizletandroid.databinding.B) matchEndGameFragment.J()).e;
                Intrinsics.checkNotNullExpressionValue(matchFinishText3, "matchFinishText");
                CharSequence text = matchFinishText3.getText();
                Intrinsics.checkNotNullExpressionValue(text, "getText(...)");
                com.facebook.appevents.cloudbridge.c.c(matchFinishText2, StringsKt.O(text));
                QTextView matchFinishSeconds = ((com.quizlet.quizletandroid.databinding.B) matchEndGameFragment.J()).d;
                Intrinsics.checkNotNullExpressionValue(matchFinishSeconds, "matchFinishSeconds");
                Context contextRequireContext2 = matchEndGameFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                matchFinishSeconds.setText(AbstractC3053s1.e(fVar, contextRequireContext2));
                QTextView matchPersonalRecord = ((com.quizlet.quizletandroid.databinding.B) matchEndGameFragment.J()).h;
                Intrinsics.checkNotNullExpressionValue(matchPersonalRecord, "matchPersonalRecord");
                Context contextRequireContext3 = matchEndGameFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                matchPersonalRecord.setText(AbstractC3053s1.e(p05.c, contextRequireContext3));
                matchEndGameFragment.X().setVisibility(0);
                K k = K.a;
                M m = p05.d;
                if (Intrinsics.b(m, k)) {
                    matchEndGameFragment.W().setText(matchEndGameFragment.getString(R.string.play_again));
                    matchEndGameFragment.X().setVisibility(8);
                    matchEndGameFragment.W().setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.f
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            MatchEndGameFragment matchEndGameFragment2 = matchEndGameFragment;
                            switch (i5) {
                                case 0:
                                    String str3 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                                case 1:
                                    String str4 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                                case 2:
                                    String str5 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(true);
                                    break;
                                case 3:
                                    String str6 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(true);
                                    break;
                                default:
                                    String str7 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                            }
                        }
                    });
                } else if (m instanceof J) {
                    matchEndGameFragment.W().setText(matchEndGameFragment.getString(R.string.play_again));
                    QButton qButtonX = matchEndGameFragment.X();
                    com.quizlet.quizletandroid.util.f fVar2 = matchEndGameFragment.j;
                    if (fVar2 == null) {
                        Intrinsics.m("languageUtil");
                        throw null;
                    }
                    Resources resources = matchEndGameFragment.getResources();
                    int i6 = ((J) m).a;
                    String quantityString = resources.getQuantityString(R.plurals.or_play_selected_terms, i6, Integer.valueOf(i6));
                    Intrinsics.checkNotNullExpressionValue(quantityString, "getQuantityString(...)");
                    qButtonX.setText(fVar2.g(quantityString));
                    matchEndGameFragment.W().setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.f
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            MatchEndGameFragment matchEndGameFragment2 = matchEndGameFragment;
                            switch (i2) {
                                case 0:
                                    String str3 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                                case 1:
                                    String str4 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                                case 2:
                                    String str5 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(true);
                                    break;
                                case 3:
                                    String str6 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(true);
                                    break;
                                default:
                                    String str7 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                            }
                        }
                    });
                    matchEndGameFragment.X().setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.f
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            MatchEndGameFragment matchEndGameFragment2 = matchEndGameFragment;
                            switch (i3) {
                                case 0:
                                    String str3 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                                case 1:
                                    String str4 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                                case 2:
                                    String str5 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(true);
                                    break;
                                case 3:
                                    String str6 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(true);
                                    break;
                                default:
                                    String str7 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                            }
                        }
                    });
                } else {
                    if (!(m instanceof L)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    QButton qButtonW = matchEndGameFragment.W();
                    com.quizlet.quizletandroid.util.f fVar3 = matchEndGameFragment.j;
                    if (fVar3 == null) {
                        Intrinsics.m("languageUtil");
                        throw null;
                    }
                    String string = matchEndGameFragment.getString(R.string.play_selected_terms_again);
                    Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                    qButtonW.setText(fVar3.g(string));
                    matchEndGameFragment.X().setText(matchEndGameFragment.getString(R.string.play_with_all_terms));
                    matchEndGameFragment.W().setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.f
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            MatchEndGameFragment matchEndGameFragment2 = matchEndGameFragment;
                            switch (i4) {
                                case 0:
                                    String str3 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                                case 1:
                                    String str4 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                                case 2:
                                    String str5 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(true);
                                    break;
                                case 3:
                                    String str6 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(true);
                                    break;
                                default:
                                    String str7 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                            }
                        }
                    });
                    matchEndGameFragment.X().setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.f
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            MatchEndGameFragment matchEndGameFragment2 = matchEndGameFragment;
                            switch (i) {
                                case 0:
                                    String str3 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                                case 1:
                                    String str4 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                                case 2:
                                    String str5 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(true);
                                    break;
                                case 3:
                                    String str6 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(true);
                                    break;
                                default:
                                    String str7 = MatchEndGameFragment.p;
                                    matchEndGameFragment2.V().C(false);
                                    break;
                            }
                        }
                    });
                }
                com.quizlet.quizletandroid.ui.common.images.capture.b bVar = com.quizlet.qutils.android.e.a;
                Context contextRequireContext4 = matchEndGameFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext4, "requireContext(...)");
                bVar.getClass();
                if (!com.quizlet.quizletandroid.ui.common.images.capture.b.j(contextRequireContext4) && (dBStudySet = (w = p05.e).b) != null) {
                    ShareSetButton matchShareSetButton = ((com.quizlet.quizletandroid.databinding.B) matchEndGameFragment.J()).l;
                    Intrinsics.checkNotNullExpressionValue(matchShareSetButton, "matchShareSetButton");
                    ShareSetButton.p(matchShareSetButton, w.a, dBStudySet, w.c);
                }
                return Unit.a;
            case 6:
                G p06 = (G) obj;
                Intrinsics.checkNotNullParameter(p06, "p0");
                MatchEndGameFragment matchEndGameFragment2 = (MatchEndGameFragment) this.receiver;
                String str3 = MatchEndGameFragment.p;
                QProgressBar matchProgressBar = ((com.quizlet.quizletandroid.databinding.B) matchEndGameFragment2.J()).k;
                Intrinsics.checkNotNullExpressionValue(matchProgressBar, "matchProgressBar");
                matchProgressBar.setVisibility(8);
                if (p06 instanceof E) {
                    E e = (E) p06;
                    List list2 = e.a;
                    matchEndGameFragment2.T().setVisibility(0);
                    matchEndGameFragment2.T().setAdapter(new com.quizlet.quizletandroid.ui.common.adapter.a(list2));
                    Context contextRequireContext5 = matchEndGameFragment2.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext5, "requireContext(...)");
                    CenterLayoutManager centerLayoutManager = new CenterLayoutManager(contextRequireContext5, 0);
                    matchEndGameFragment2.T().setLayoutManager(centerLayoutManager);
                    int i7 = e.b;
                    centerLayoutManager.v0(i7);
                    RecyclerView recyclerViewT = matchEndGameFragment2.T();
                    recyclerViewT.getViewTreeObserver().addOnGlobalLayoutListener(new com.quizlet.diagrams.text.a(recyclerViewT, matchEndGameFragment2, i7, i3));
                } else if (p06 instanceof D) {
                    D d = (D) p06;
                    com.quizlet.qutils.string.f fVar4 = d.a;
                    matchEndGameFragment2.T().setVisibility(8);
                    QTextView matchPersonalRecord2 = ((com.quizlet.quizletandroid.databinding.B) matchEndGameFragment2.J()).h;
                    Intrinsics.checkNotNullExpressionValue(matchPersonalRecord2, "matchPersonalRecord");
                    matchPersonalRecord2.setVisibility(8);
                    QTextView matchError = ((com.quizlet.quizletandroid.databinding.B) matchEndGameFragment2.J()).c;
                    Intrinsics.checkNotNullExpressionValue(matchError, "matchError");
                    matchError.setVisibility(0);
                    Context contextRequireContext6 = matchEndGameFragment2.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext6, "requireContext(...)");
                    String strE = AbstractC3053s1.e(fVar4, contextRequireContext6);
                    QTextView matchError2 = ((com.quizlet.quizletandroid.databinding.B) matchEndGameFragment2.J()).c;
                    Intrinsics.checkNotNullExpressionValue(matchError2, "matchError");
                    CharSequence charSequence = strE;
                    if (d.b) {
                        CharSequence charSequenceFromHtml = Html.fromHtml(strE, 0);
                        Intrinsics.checkNotNullExpressionValue(charSequenceFromHtml, "fromHtml(...)");
                        charSequence = charSequenceFromHtml;
                    }
                    matchError2.setText(charSequence);
                } else {
                    if (!Intrinsics.b(p06, F.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    matchEndGameFragment2.T().setVisibility(8);
                    QTextView matchPersonalRecord3 = ((com.quizlet.quizletandroid.databinding.B) matchEndGameFragment2.J()).h;
                    Intrinsics.checkNotNullExpressionValue(matchPersonalRecord3, "matchPersonalRecord");
                    matchPersonalRecord3.setVisibility(8);
                }
                return Unit.a;
            case 7:
                Z state = (Z) obj;
                Intrinsics.checkNotNullParameter(state, "p0");
                com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g gVar2 = (com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g) this.receiver;
                gVar2.getClass();
                Intrinsics.checkNotNullParameter(state, "state");
                gVar2.r.j(state);
                return Unit.a;
            case 8:
                a0 p07 = (a0) obj;
                Intrinsics.checkNotNullParameter(p07, "p0");
                MatchEndGameFragment matchEndGameFragment3 = (MatchEndGameFragment) this.receiver;
                String str4 = MatchEndGameFragment.p;
                AbstractC1136h0 parentFragmentManager = matchEndGameFragment3.getParentFragmentManager();
                String str5 = ChallengeDialogFragment.B;
                if (parentFragmentManager.E(str5) == null) {
                    double d2 = p07.a;
                    ChallengeDialogFragment challengeDialogFragment = new ChallengeDialogFragment();
                    Bundle bundle = new Bundle();
                    bundle.putDouble("scoreInSeconds", d2);
                    bundle.putString("profileImageUrl", p07.b);
                    bundle.putString("username", p07.c);
                    challengeDialogFragment.setArguments(bundle);
                    challengeDialogFragment.O(matchEndGameFragment3.getParentFragmentManager(), str5);
                }
                return Unit.a;
            case 9:
                AbstractC4367x p08 = (AbstractC4367x) obj;
                Intrinsics.checkNotNullParameter(p08, "p0");
                MatchGameFragment matchGameFragment = (MatchGameFragment) this.receiver;
                String str6 = MatchGameFragment.m;
                com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g gVarT = matchGameFragment.T();
                N screen2 = N.b;
                gVarT.getClass();
                Intrinsics.checkNotNullParameter(screen2, "screen");
                gVarT.l.o(screen2);
                if (p08 instanceof C4366w) {
                    int iOrdinal = ((C4366w) p08).a.ordinal();
                    if (iOrdinal == 0) {
                        StandardMatchGameFragment standardMatchGameFragment = new StandardMatchGameFragment();
                        String str7 = StandardMatchGameFragment.r;
                        if (matchGameFragment.getChildFragmentManager().E(str7) == null) {
                            AbstractC1136h0 childFragmentManager = matchGameFragment.getChildFragmentManager();
                            childFragmentManager.getClass();
                            C1121a c1121a = new C1121a(childFragmentManager);
                            c1121a.l(R.id.gameContainer, standardMatchGameFragment, str7);
                            c1121a.g();
                        }
                    } else {
                        if (iOrdinal != 1) {
                            throw new NoWhenBranchMatchedException();
                        }
                        DiagramMatchGameFragment diagramMatchGameFragment = new DiagramMatchGameFragment();
                        String str8 = DiagramMatchGameFragment.t;
                        if (matchGameFragment.getChildFragmentManager().E(str8) == null) {
                            AbstractC1136h0 childFragmentManager2 = matchGameFragment.getChildFragmentManager();
                            childFragmentManager2.getClass();
                            C1121a c1121a2 = new C1121a(childFragmentManager2);
                            c1121a2.l(R.id.gameContainer, diagramMatchGameFragment, str8);
                            c1121a2.g();
                        }
                    }
                } else if (p08 instanceof C4364u) {
                    C4364u c4364u = (C4364u) p08;
                    long j = c4364u.a;
                    com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g gVarT2 = matchGameFragment.T();
                    gVarT2.getClass();
                    kotlinx.coroutines.E.A(p0.j(gVarT2), null, null, new com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.d(gVarT2, j, c4364u.b, null), 3);
                } else {
                    if (!(p08 instanceof C4365v)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g gVarT3 = matchGameFragment.T();
                    gVarT3.getClass();
                    kotlinx.coroutines.E.A(p0.j(gVarT3), null, null, new com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.b(gVarT3, null), 3);
                }
                return Unit.a;
            case 10:
                T p09 = (T) obj;
                Intrinsics.checkNotNullParameter(p09, "p0");
                final MatchStartGameFragment matchStartGameFragment = (MatchStartGameFragment) this.receiver;
                String str9 = MatchStartGameFragment.n;
                com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g gVarT4 = matchStartGameFragment.T();
                N screen3 = N.a;
                gVarT4.getClass();
                Intrinsics.checkNotNullParameter(screen3, "screen");
                gVarT4.l.o(screen3);
                matchStartGameFragment.V().setVisibility(0);
                int iOrdinal2 = p09.ordinal();
                if (iOrdinal2 == 0) {
                    matchStartGameFragment.U().setText(matchStartGameFragment.getString(R.string.match_start_game));
                    matchStartGameFragment.V().setVisibility(8);
                    matchStartGameFragment.U().setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.m
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            MatchStartGameFragment matchStartGameFragment2 = matchStartGameFragment;
                            switch (i5) {
                                case 0:
                                    String str10 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                                case 1:
                                    String str11 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                                case 2:
                                    String str12 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(true);
                                    break;
                                case 3:
                                    String str13 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(true);
                                    break;
                                default:
                                    String str14 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                            }
                        }
                    });
                } else if (iOrdinal2 == 1) {
                    matchStartGameFragment.U().setText(matchStartGameFragment.getString(R.string.match_start_game));
                    matchStartGameFragment.V().setText(matchStartGameFragment.getString(R.string.match_start_selected_terms_mode));
                    matchStartGameFragment.U().setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.m
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            MatchStartGameFragment matchStartGameFragment2 = matchStartGameFragment;
                            switch (i2) {
                                case 0:
                                    String str10 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                                case 1:
                                    String str11 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                                case 2:
                                    String str12 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(true);
                                    break;
                                case 3:
                                    String str13 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(true);
                                    break;
                                default:
                                    String str14 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                            }
                        }
                    });
                    matchStartGameFragment.V().setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.m
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            MatchStartGameFragment matchStartGameFragment2 = matchStartGameFragment;
                            switch (i3) {
                                case 0:
                                    String str10 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                                case 1:
                                    String str11 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                                case 2:
                                    String str12 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(true);
                                    break;
                                case 3:
                                    String str13 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(true);
                                    break;
                                default:
                                    String str14 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                            }
                        }
                    });
                } else {
                    if (iOrdinal2 != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    matchStartGameFragment.U().setText(matchStartGameFragment.getString(R.string.match_start_selected_terms_mode));
                    matchStartGameFragment.V().setText(matchStartGameFragment.getString(R.string.match_start_game_all));
                    matchStartGameFragment.U().setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.m
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            MatchStartGameFragment matchStartGameFragment2 = matchStartGameFragment;
                            switch (i4) {
                                case 0:
                                    String str10 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                                case 1:
                                    String str11 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                                case 2:
                                    String str12 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(true);
                                    break;
                                case 3:
                                    String str13 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(true);
                                    break;
                                default:
                                    String str14 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                            }
                        }
                    });
                    matchStartGameFragment.V().setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.studymodes.match.fragment.m
                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view) {
                            MatchStartGameFragment matchStartGameFragment2 = matchStartGameFragment;
                            switch (i) {
                                case 0:
                                    String str10 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                                case 1:
                                    String str11 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                                case 2:
                                    String str12 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(true);
                                    break;
                                case 3:
                                    String str13 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(true);
                                    break;
                                default:
                                    String str14 = MatchStartGameFragment.n;
                                    matchStartGameFragment2.T().C(false);
                                    break;
                            }
                        }
                    });
                }
                return Unit.a;
            case 11:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                MatchStartGameFragment matchStartGameFragment2 = (MatchStartGameFragment) this.receiver;
                String str10 = MatchStartGameFragment.n;
                androidx.lifecycle.J viewLifecycleOwner = matchStartGameFragment2.getViewLifecycleOwner();
                Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
                kotlinx.coroutines.E.A(p0.h(viewLifecycleOwner), null, null, new com.quizlet.quizletandroid.ui.studymodes.match.fragment.n(zBooleanValue, matchStartGameFragment2, null), 3);
                return Unit.a;
            case 12:
                C4761c event2 = (C4761c) obj;
                Intrinsics.checkNotNullParameter(event2, "p0");
                com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t tVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t) this.receiver;
                tVar.getClass();
                Intrinsics.checkNotNullParameter(event2, "event");
                if (!(event2 instanceof C4761c)) {
                    throw new NoWhenBranchMatchedException();
                }
                String str11 = event2.a;
                y0 y0Var = tVar.e;
                if (y0Var != null) {
                    y0Var.j(null);
                }
                tVar.e = kotlinx.coroutines.E.A(p0.j(tVar), null, null, new com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.q(tVar, str11, null), 3);
                return Unit.a;
            case 13:
                androidx.compose.ui.text.input.A p010 = (androidx.compose.ui.text.input.A) obj;
                Intrinsics.checkNotNullParameter(p010, "p0");
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.A a = (com.quizlet.quizletandroid.ui.studymodes.testmode.start.A) this.receiver;
                Object value4 = a.h.getValue();
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.c cVar2 = value4 instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.start.c ? (com.quizlet.quizletandroid.ui.studymodes.testmode.start.c) value4 : null;
                if (cVar2 != null) {
                    boolean zO = StringsKt.O(p010.a.a);
                    C0995g c0995g = p010.a;
                    if (zO) {
                        strValueOf = c0995g.a;
                    } else {
                        Integer intOrNull = StringsKt.toIntOrNull(c0995g.a);
                        strValueOf = String.valueOf(Math.min(intOrNull != null ? intOrNull.intValue() : a.j, a.j));
                    }
                    int length = strValueOf.length();
                    a.G(com.quizlet.quizletandroid.ui.studymodes.testmode.start.c.a(cVar2, new androidx.compose.ui.text.input.A(4, AbstractC3205m5.c(length, length), strValueOf), null, null, null, null, false, null, 4093));
                }
                return Unit.a;
            case 14:
                boolean zBooleanValue2 = ((Boolean) obj).booleanValue();
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.A a2 = (com.quizlet.quizletandroid.ui.studymodes.testmode.start.A) this.receiver;
                Object value5 = a2.h.getValue();
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.c cVar3 = value5 instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.start.c ? (com.quizlet.quizletandroid.ui.studymodes.testmode.start.c) value5 : null;
                if (cVar3 != null) {
                    a2.G(com.quizlet.quizletandroid.ui.studymodes.testmode.start.c.a(cVar3, null, com.quizlet.quizletandroid.ui.studymodes.testmode.start.j.a(cVar3.e, zBooleanValue2), null, null, null, false, null, 4079));
                }
                return Unit.a;
            case 15:
                boolean zBooleanValue3 = ((Boolean) obj).booleanValue();
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.A a3 = (com.quizlet.quizletandroid.ui.studymodes.testmode.start.A) this.receiver;
                Object value6 = a3.h.getValue();
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.c cVar4 = value6 instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.start.c ? (com.quizlet.quizletandroid.ui.studymodes.testmode.start.c) value6 : null;
                if (cVar4 != null) {
                    a3.G(com.quizlet.quizletandroid.ui.studymodes.testmode.start.c.a(cVar4, null, null, com.quizlet.quizletandroid.ui.studymodes.testmode.start.j.a(cVar4.f, zBooleanValue3), null, null, false, null, 4063));
                }
                return Unit.a;
            case 16:
                boolean zBooleanValue4 = ((Boolean) obj).booleanValue();
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.A a4 = (com.quizlet.quizletandroid.ui.studymodes.testmode.start.A) this.receiver;
                Object value7 = a4.h.getValue();
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.c cVar5 = value7 instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.start.c ? (com.quizlet.quizletandroid.ui.studymodes.testmode.start.c) value7 : null;
                if (cVar5 != null) {
                    a4.G(com.quizlet.quizletandroid.ui.studymodes.testmode.start.c.a(cVar5, null, null, null, null, com.quizlet.quizletandroid.ui.studymodes.testmode.start.j.a(cVar5.h, zBooleanValue4), false, null, 3967));
                }
                return Unit.a;
            case 17:
                boolean zBooleanValue5 = ((Boolean) obj).booleanValue();
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.A a5 = (com.quizlet.quizletandroid.ui.studymodes.testmode.start.A) this.receiver;
                Object value8 = a5.h.getValue();
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.c cVar6 = value8 instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.start.c ? (com.quizlet.quizletandroid.ui.studymodes.testmode.start.c) value8 : null;
                if (cVar6 != null) {
                    a5.G(com.quizlet.quizletandroid.ui.studymodes.testmode.start.c.a(cVar6, null, null, null, com.quizlet.quizletandroid.ui.studymodes.testmode.start.j.a(cVar6.g, zBooleanValue5), null, false, null, 4031));
                }
                return Unit.a;
            case 18:
                K1 subject = (K1) obj;
                Intrinsics.checkNotNullParameter(subject, "p0");
                com.quizlet.quizletandroid.ui.subject.viewmodel.m mVar = (com.quizlet.quizletandroid.ui.subject.viewmodel.m) this.receiver;
                mVar.getClass();
                Intrinsics.checkNotNullParameter(subject, "subject");
                kotlinx.coroutines.E.A(p0.j(mVar), null, null, new com.quizlet.quizletandroid.ui.subject.viewmodel.l(mVar, subject, null), 3);
                return Unit.a;
            case 19:
                ChangeProfileImageFragment changeProfileImageFragment = (ChangeProfileImageFragment) this.receiver;
                String str12 = ChangeProfileImageFragment.w;
                changeProfileImageFragment.getClass();
                timber.log.c.a.p((Throwable) obj);
                Intent intent = new Intent();
                intent.putExtra("EXTRA_ERROR", changeProfileImageFragment.getString(R.string.user_settings_load_profile_images_error));
                if (changeProfileImageFragment.getTargetFragment() != null) {
                    changeProfileImageFragment.getTargetFragment().onActivityResult(changeProfileImageFragment.getTargetRequestCode(), 2, intent);
                } else {
                    changeProfileImageFragment.getActivity().setResult(2, intent);
                    changeProfileImageFragment.getActivity().finish();
                }
                return Unit.a;
            case 20:
                ApiResponse apiResponse = (ApiResponse) obj;
                CropImageFragment cropImageFragment = (CropImageFragment) this.receiver;
                String str13 = CropImageFragment.s;
                cropImageFragment.getClass();
                if (apiResponse == null || apiResponse.getModelWrapper() == null || apiResponse.getModelWrapper().getProfileImages() == null || apiResponse.getModelWrapper().getProfileImages().size() == 0) {
                    timber.log.c.a.e(new RuntimeException("empty response, or no images returned"));
                } else {
                    timber.log.c.a.a("Image uploaded successfully", new Object[0]);
                    String id = apiResponse.getModelWrapper().getProfileImages().get(0).getId();
                    Intrinsics.checkNotNullExpressionValue(id, "getId(...)");
                    Intent intent2 = new Intent();
                    intent2.putExtra("EXTRA_PROFILE_IMAGE_ID", id);
                    Fragment targetFragment = cropImageFragment.getTargetFragment();
                    if (targetFragment != null) {
                        targetFragment.onActivityResult(cropImageFragment.getTargetRequestCode(), -1, intent2);
                    } else {
                        cropImageFragment.requireActivity().setResult(-1, intent2);
                        cropImageFragment.requireActivity().finish();
                    }
                }
                return Unit.a;
            case 21:
                Throwable p011 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(p011, "p0");
                CropImageFragment cropImageFragment2 = (CropImageFragment) this.receiver;
                String str14 = CropImageFragment.s;
                cropImageFragment2.getClass();
                timber.log.c.a.q(p011, "Error uploading new profile image", new Object[0]);
                String string2 = cropImageFragment2.getString(R.string.user_settings_profile_image_upload_error);
                View viewFindViewById = cropImageFragment2.getActivity().findViewById(R.id.coordinator_layout);
                if (viewFindViewById != null) {
                    com.google.android.material.snackbar.h hVarE = I6.e(viewFindViewById, string2);
                    hVarE.k = 0;
                    hVarE.i();
                }
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                com.quizlet.report.data.h event3 = (com.quizlet.report.data.h) obj;
                Intrinsics.checkNotNullParameter(event3, "p0");
                com.quizlet.report.viewmodels.c cVar7 = (com.quizlet.report.viewmodels.c) ((com.quizlet.report.viewmodels.a) this.receiver);
                cVar7.getClass();
                Intrinsics.checkNotNullParameter(event3, "event");
                if (Intrinsics.b(event3, com.quizlet.report.data.e.a)) {
                    cVar7.g.h(new com.quizlet.report.data.i(new com.quizlet.report.ui.b(cVar7.e)));
                } else {
                    boolean z = event3 instanceof com.quizlet.report.data.f;
                    s0 s0Var2 = cVar7.f;
                    if (z) {
                        int i8 = ((com.quizlet.report.data.f) event3).a;
                        com.quizlet.report.data.a aVar = (com.quizlet.report.data.a) ((com.quizlet.report.data.o) s0Var2.getValue()).a.a().get(i8);
                        if (aVar.c) {
                            cVar7.h = ((com.quizlet.report.data.o) s0Var2.getValue()).a;
                            cVar7.i = Integer.valueOf(i8);
                            com.quizlet.report.data.n nVar = aVar.b;
                            if (nVar != null) {
                                do {
                                    value2 = s0Var2.getValue();
                                } while (!s0Var2.k(value2, com.quizlet.report.data.o.a((com.quizlet.report.data.o) value2, nVar, null, false, true, false, null, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY)));
                            }
                        } else {
                            Q0 q0 = aVar.a;
                            if (q0 != null) {
                                kotlinx.coroutines.E.A(p0.j(cVar7), null, null, new com.quizlet.report.viewmodels.b(cVar7, q0, null), 3);
                            }
                        }
                    } else {
                        if (!Intrinsics.b(event3, com.quizlet.report.data.g.a)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        com.quizlet.report.data.n nVar2 = cVar7.h;
                        if (nVar2 != null) {
                            do {
                                value = s0Var2.getValue();
                            } while (!s0Var2.k(value, com.quizlet.report.data.o.a((com.quizlet.report.data.o) value, nVar2, cVar7.i, false, false, false, null, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY)));
                        }
                        cVar7.h = null;
                        cVar7.i = null;
                    }
                }
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                com.quizlet.ui.models.impressions.a model = (com.quizlet.ui.models.impressions.a) obj;
                Intrinsics.checkNotNullParameter(model, "p0");
                com.quizlet.search.viewmodels.r rVar = (com.quizlet.search.viewmodels.r) this.receiver;
                rVar.getClass();
                Intrinsics.checkNotNullParameter(model, "model");
                com.quizlet.search.data.blended.i iVar = (com.quizlet.search.data.blended.i) rVar.e.getValue();
                if (!Intrinsics.b(iVar, com.quizlet.search.data.blended.g.a)) {
                    if (!(iVar instanceof com.quizlet.search.data.blended.h)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    List list3 = ((com.quizlet.search.data.blended.h) iVar).a;
                    ArrayList arrayList = new ArrayList();
                    for (Object obj2 : list3) {
                        if (!(((com.quizlet.ui.models.search.a) obj2) instanceof com.quizlet.search.data.b)) {
                            arrayList.add(obj2);
                        }
                    }
                    Intrinsics.e(model, "null cannot be cast to non-null type com.quizlet.ui.models.search.BaseSearchUiModel");
                    iIndexOf = arrayList.indexOf((com.quizlet.ui.models.search.a) model) + 1;
                }
                rVar.c.o(model.getModelType(), model.getItemId(), iIndexOf, rVar.d, model.a());
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                String query = (String) obj;
                Intrinsics.checkNotNullParameter(query, "p0");
                com.quizlet.search.viewmodels.p pVar = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar.getClass();
                Intrinsics.checkNotNullParameter(query, "query");
                y0 y0Var2 = pVar.m;
                if (y0Var2 != null) {
                    y0Var2.j(null);
                }
                pVar.n = query;
                if (query.length() == 0) {
                    do {
                        s0Var = pVar.i;
                        value3 = s0Var.getValue();
                    } while (!s0Var.k(value3, com.quizlet.search.data.e.a));
                } else {
                    pVar.m = kotlinx.coroutines.E.A(p0.j(pVar), pVar.l, null, new com.quizlet.search.viewmodels.n(pVar, query, null), 2);
                }
                return Unit.a;
            case EventType.SUBS /* 25 */:
                com.quizlet.ui.models.search.c searchShortcutModel = (com.quizlet.ui.models.search.c) obj;
                Intrinsics.checkNotNullParameter(searchShortcutModel, "p0");
                com.quizlet.search.viewmodels.p pVar2 = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar2.getClass();
                Intrinsics.checkNotNullParameter(searchShortcutModel, "searchShortcutModel");
                kotlinx.coroutines.E.A(p0.j(pVar2), null, null, new C4806l(pVar2, searchShortcutModel, null), 3);
                return Unit.a;
            case EventType.CDN /* 26 */:
                String suggestion = (String) obj;
                Intrinsics.checkNotNullParameter(suggestion, "p0");
                com.quizlet.search.viewmodels.p pVar3 = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar3.getClass();
                Intrinsics.checkNotNullParameter(suggestion, "suggestion");
                pVar3.n = suggestion;
                com.quizlet.search.logging.b bVar2 = pVar3.c;
                bVar2.getClass();
                Intrinsics.checkNotNullParameter(suggestion, "suggestion");
                if (bVar2.b.b.length() != 0) {
                    SearchEventsEventLog searchEventsEventLogA = SearchEventsEventLog.Companion.a(SearchEventsEventLog.b, bVar2.b.a, EnumC4466a1.TYPEAHEAD_CLICKED_SUGGESTED_RESULT.a(), bVar2.b.b, null, null, null, null, null, null, null, null, null, null, 16376);
                    searchEventsEventLogA.getPayload().setSuggestion(suggestion);
                    bVar2.a.l(searchEventsEventLogA);
                }
                pVar3.B(suggestion, true);
                return Unit.a;
            case 27:
                com.quizlet.search.data.c searchUiData = (com.quizlet.search.data.c) obj;
                Intrinsics.checkNotNullParameter(searchUiData, "p0");
                com.quizlet.search.viewmodels.p pVar4 = (com.quizlet.search.viewmodels.p) this.receiver;
                pVar4.getClass();
                Intrinsics.checkNotNullParameter(searchUiData, "searchUiData");
                int iOrdinal3 = searchUiData.c.ordinal();
                String str15 = searchUiData.a;
                String str16 = searchUiData.b;
                if (iOrdinal3 == 0) {
                    str = str15;
                } else if (iOrdinal3 == 1) {
                    str = str16;
                } else if (iOrdinal3 != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                if (str != null) {
                    int iOrdinal4 = searchUiData.c.ordinal();
                    if (iOrdinal4 == 0) {
                        enumC4466a1 = EnumC4466a1.MISSPELLINGS_ORIGINAL_QUERY_CLICK;
                    } else {
                        if (iOrdinal4 != 1) {
                            if (iOrdinal4 != 2) {
                                throw new NoWhenBranchMatchedException();
                            }
                            throw new IllegalArgumentException("MisspellingsType.None should not be clickable");
                        }
                        enumC4466a1 = EnumC4466a1.MISSPELLINGS_CORRECTED_QUERY_CLICK;
                    }
                    pVar4.f.d(str15, str16, enumC4466a1);
                    pVar4.B(str, false);
                }
                return Unit.a;
            case 28:
                String enumValue = (String) obj;
                Intrinsics.checkNotNullParameter(enumValue, "p0");
                com.quizlet.search.viewmodels.A a6 = (com.quizlet.search.viewmodels.A) this.receiver;
                a6.getClass();
                Intrinsics.checkNotNullParameter(enumValue, "enumValue");
                a6.k.t(enumValue);
                return Unit.a;
            default:
                String enumValue2 = (String) obj;
                Intrinsics.checkNotNullParameter(enumValue2, "p0");
                com.quizlet.search.viewmodels.A a7 = (com.quizlet.search.viewmodels.A) this.receiver;
                a7.getClass();
                Intrinsics.checkNotNullParameter(enumValue2, "enumValue");
                a7.k.m(enumValue2);
                return Unit.a;
        }
    }
}
