package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import android.content.Context;
import android.os.Bundle;
import android.os.Parcelable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.animation.d0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.z1;
import com.quizlet.learn.data.C4536a;
import com.quizlet.learn.viewmodel.G;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class LAResultsFragment extends Hilt_LAResultsFragment<androidx.viewbinding.a> {
    public static final String n;
    public static final String o;
    public com.quizlet.infra.legacysyncengine.managers.d j;
    public EventLogger k;
    public StudyModeEventLogger l;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e m = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(G.class), new d(this, 0), new d(this, 2), new d(this, 1));

    static {
        Intrinsics.checkNotNullExpressionValue("LAResultsFragment", "getSimpleName(...)");
        n = "LAResultsFragment";
        o = "results";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return n;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 25);
    }

    public final void T(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1066892423);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i2 = (int) requireArguments().getDouble("KEY_STUDY_PROGRESS");
            AbstractC3178j5.b(null, false, null, androidx.compose.runtime.internal.e.e(-2130361127, new com.quizlet.features.practicetest.results.i(23, new C4536a(AbstractC3691o6.e(i2), 5, AbstractC3691o6.d(i2)), this), c0814p), c0814p, 3072, 7);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(this, i, 11);
        }
    }

    public final StudyEventLogData U() {
        Parcelable parcelable = requireArguments().getParcelable("KEY_STUDY_EVENT_DATA");
        if (parcelable != null) {
            return (StudyEventLogData) parcelable;
        }
        throw new IllegalArgumentException("Required value was null.");
    }

    public final StudyableModelData V() {
        Parcelable parcelable = requireArguments().getParcelable("KEY_STUDYABLE_DATA");
        if (parcelable != null) {
            return (StudyableModelData) parcelable;
        }
        throw new IllegalArgumentException("Required value was null.");
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        timber.log.c.a.g("Showing RESULTS", new Object[0]);
        EventLogger eventLogger = this.k;
        if (eventLogger == null) {
            Intrinsics.m("eventLogger");
            throw null;
        }
        z1 z1Var = A1.Companion;
        int i = requireArguments().getInt("KEY_MODE_TYPE");
        z1Var.getClass();
        StudyModeEventLogger studyModeEventLogger = new StudyModeEventLogger(eventLogger, z1.a(i));
        Intrinsics.checkNotNullParameter(studyModeEventLogger, "<set-?>");
        this.l = studyModeEventLogger;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        StudyModeEventLogger studyModeEventLogger = this.l;
        if (studyModeEventLogger == null) {
            Intrinsics.m("studyModeEventLogger");
            throw null;
        }
        StudyEventLogData studyEventLogDataU = U();
        studyModeEventLogger.e(studyEventLogDataU.a, V().getStudyableType(), 1, null, Long.valueOf(U().b), Long.valueOf(U().c), Boolean.valueOf(U().d), o, null);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStop() {
        StudyModeEventLogger studyModeEventLogger = this.l;
        if (studyModeEventLogger == null) {
            Intrinsics.m("studyModeEventLogger");
            throw null;
        }
        StudyEventLogData studyEventLogDataU = U();
        studyModeEventLogger.f(studyEventLogDataU.a, V().getStudyableType(), 1, null, Long.valueOf(U().b), Long.valueOf(U().c), Boolean.valueOf(U().d), o);
        super.onStop();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        long jCurrentTimeMillis = System.currentTimeMillis();
        Context context = getContext();
        if (context == null) {
            return;
        }
        com.quizlet.quizletandroid.ui.studymodes.assistant.a aVar = new com.quizlet.quizletandroid.ui.studymodes.assistant.a(context);
        long jK = V().k();
        com.quizlet.infra.legacysyncengine.managers.d dVar = this.j;
        if (dVar == null) {
            Intrinsics.m("loggedInUserManager");
            throw null;
        }
        aVar.a.edit().putLong(d0.s(new Object[]{Long.valueOf(jK), Long.valueOf(dVar.e.getPersonId())}, 2, "aprt_pref_%s_%s", "format(...)"), jCurrentTimeMillis).apply();
    }
}
