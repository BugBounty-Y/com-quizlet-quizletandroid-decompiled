package com.quizlet.quizletandroid.ui.studymodes.match.settings;

import android.content.Intent;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Parcelable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CompoundButton;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.ScrollView;
import androidx.fragment.app.I;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.O6;
import com.quizlet.assembly.widgets.toggle.AssemblyToggleSwitch;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import com.quizlet.features.match.settings.MatchSettingsData;
import com.quizlet.generated.enums.G1;
import com.quizlet.generated.enums.O1;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.O;
import com.quizlet.quizletandroid.ui.common.adapter.viewholder.h;
import com.quizlet.uicommon.ui.common.widgets.QSegmentedControl;
import com.quizlet.uicommon.ui.common.widgets.i;
import java.util.Arrays;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class MatchSettingsFragment extends Hilt_MatchSettingsFragment<O> {
    public static final String k;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.a j;

    static {
        Intrinsics.checkNotNullExpressionValue("MatchSettingsFragment", "getSimpleName(...)");
        k = "MatchSettingsFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return k;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.match_settings_fragment, viewGroup, false);
        int i = R.id.match_settings_definition_switch;
        AssemblyToggleSwitch assemblyToggleSwitch = (AssemblyToggleSwitch) AbstractC3375o2.c(R.id.match_settings_definition_switch, viewInflate);
        if (assemblyToggleSwitch != null) {
            i = R.id.match_settings_definition_switch_layout;
            RelativeLayout relativeLayout = (RelativeLayout) AbstractC3375o2.c(R.id.match_settings_definition_switch_layout, viewInflate);
            if (relativeLayout != null) {
                i = R.id.match_settings_general_group;
                LinearLayout linearLayout = (LinearLayout) AbstractC3375o2.c(R.id.match_settings_general_group, viewInflate);
                if (linearLayout != null) {
                    i = R.id.match_settings_location_switch;
                    AssemblyToggleSwitch assemblyToggleSwitch2 = (AssemblyToggleSwitch) AbstractC3375o2.c(R.id.match_settings_location_switch, viewInflate);
                    if (assemblyToggleSwitch2 != null) {
                        i = R.id.match_settings_location_switch_layout;
                        RelativeLayout relativeLayout2 = (RelativeLayout) AbstractC3375o2.c(R.id.match_settings_location_switch_layout, viewInflate);
                        if (relativeLayout2 != null) {
                            i = R.id.match_settings_match_group_status;
                            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.match_settings_match_group_status, viewInflate);
                            if (qTextView != null) {
                                i = R.id.match_settings_match_group_status_error;
                                QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.match_settings_match_group_status_error, viewInflate);
                                if (qTextView2 != null) {
                                    i = R.id.match_settings_restart_match_button;
                                    RelativeLayout relativeLayout3 = (RelativeLayout) AbstractC3375o2.c(R.id.match_settings_restart_match_button, viewInflate);
                                    if (relativeLayout3 != null) {
                                        i = R.id.match_settings_restart_match_button_text;
                                        QTextView qTextView3 = (QTextView) AbstractC3375o2.c(R.id.match_settings_restart_match_button_text, viewInflate);
                                        if (qTextView3 != null) {
                                            i = R.id.match_settings_selected_terms_filter_control;
                                            QSegmentedControl qSegmentedControl = (QSegmentedControl) AbstractC3375o2.c(R.id.match_settings_selected_terms_filter_control, viewInflate);
                                            if (qSegmentedControl != null) {
                                                i = R.id.match_settings_term_switch;
                                                AssemblyToggleSwitch assemblyToggleSwitch3 = (AssemblyToggleSwitch) AbstractC3375o2.c(R.id.match_settings_term_switch, viewInflate);
                                                if (assemblyToggleSwitch3 != null) {
                                                    i = R.id.match_settings_term_switch_layout;
                                                    RelativeLayout relativeLayout4 = (RelativeLayout) AbstractC3375o2.c(R.id.match_settings_term_switch_layout, viewInflate);
                                                    if (relativeLayout4 != null) {
                                                        O o = new O((ScrollView) viewInflate, assemblyToggleSwitch, relativeLayout, linearLayout, assemblyToggleSwitch2, relativeLayout2, qTextView, qTextView2, relativeLayout3, qTextView3, qSegmentedControl, assemblyToggleSwitch3, relativeLayout4);
                                                        Intrinsics.checkNotNullExpressionValue(o, "inflate(...)");
                                                        return o;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final MatchSettingsData T() {
        QSegmentedControl matchSettingsSelectedTermsFilterControl = ((O) J()).k;
        Intrinsics.checkNotNullExpressionValue(matchSettingsSelectedTermsFilterControl, "matchSettingsSelectedTermsFilterControl");
        boolean z = false;
        boolean z2 = matchSettingsSelectedTermsFilterControl.getCheckedSegment() == i.c;
        RelativeLayout matchSettingsTermSwitchLayout = ((O) J()).m;
        Intrinsics.checkNotNullExpressionValue(matchSettingsTermSwitchLayout, "matchSettingsTermSwitchLayout");
        boolean z3 = matchSettingsTermSwitchLayout.getVisibility() == 0 && X().isChecked();
        RelativeLayout matchSettingsDefinitionSwitchLayout = ((O) J()).c;
        Intrinsics.checkNotNullExpressionValue(matchSettingsDefinitionSwitchLayout, "matchSettingsDefinitionSwitchLayout");
        boolean z4 = matchSettingsDefinitionSwitchLayout.getVisibility() == 0 && U().isChecked();
        RelativeLayout matchSettingsLocationSwitchLayout = ((O) J()).f;
        Intrinsics.checkNotNullExpressionValue(matchSettingsLocationSwitchLayout, "matchSettingsLocationSwitchLayout");
        if (matchSettingsLocationSwitchLayout.getVisibility() == 0 && V().isChecked()) {
            z = true;
        }
        return new MatchSettingsData(z2, z3, z4, z);
    }

    public final AssemblyToggleSwitch U() {
        AssemblyToggleSwitch matchSettingsDefinitionSwitch = ((O) J()).b;
        Intrinsics.checkNotNullExpressionValue(matchSettingsDefinitionSwitch, "matchSettingsDefinitionSwitch");
        return matchSettingsDefinitionSwitch;
    }

    public final AssemblyToggleSwitch V() {
        AssemblyToggleSwitch matchSettingsLocationSwitch = ((O) J()).e;
        Intrinsics.checkNotNullExpressionValue(matchSettingsLocationSwitch, "matchSettingsLocationSwitch");
        return matchSettingsLocationSwitch;
    }

    public final com.onetrust.otpublishers.headless.UI.TVUI.datautils.a W() {
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.a aVar = this.j;
        if (aVar != null) {
            return aVar;
        }
        Intrinsics.m("presenter");
        throw null;
    }

    public final AssemblyToggleSwitch X() {
        AssemblyToggleSwitch matchSettingsTermSwitch = ((O) J()).l;
        Intrinsics.checkNotNullExpressionValue(matchSettingsTermSwitch, "matchSettingsTermSwitch");
        return matchSettingsTermSwitch;
    }

    public final void Y(MatchSettingsData settingsToBeSaved, boolean z) {
        Intrinsics.checkNotNullParameter(settingsToBeSaved, "settingsToBeSaved");
        I iRequireActivity = requireActivity();
        Intent intent = new Intent();
        intent.putExtra("settings", settingsToBeSaved);
        intent.putExtra("shouldRestart", z);
        Unit unit = Unit.a;
        iRequireActivity.setResult(-1, intent);
    }

    public final void a0() {
        int i;
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.a aVarW = W();
        RelativeLayout matchSettingsTermSwitchLayout = ((O) J()).m;
        Intrinsics.checkNotNullExpressionValue(matchSettingsTermSwitchLayout, "matchSettingsTermSwitchLayout");
        boolean z = matchSettingsTermSwitchLayout.getVisibility() == 0 && X().isChecked();
        RelativeLayout matchSettingsDefinitionSwitchLayout = ((O) J()).c;
        Intrinsics.checkNotNullExpressionValue(matchSettingsDefinitionSwitchLayout, "matchSettingsDefinitionSwitchLayout");
        boolean z2 = matchSettingsDefinitionSwitchLayout.getVisibility() == 0 && U().isChecked();
        RelativeLayout matchSettingsLocationSwitchLayout = ((O) J()).f;
        Intrinsics.checkNotNullExpressionValue(matchSettingsLocationSwitchLayout, "matchSettingsLocationSwitchLayout");
        boolean z3 = matchSettingsLocationSwitchLayout.getVisibility() == 0 && V().isChecked();
        int[] iArr = new int[0];
        if (z && z2 && z3) {
            i = R.string.match_settings_status_with_three_selected;
        } else {
            if (z && z2 && !z3) {
                iArr = new int[]{R.string.match_settings_status_term, R.string.match_settings_status_definition};
            } else if (z && !z2 && z3) {
                iArr = new int[]{R.string.match_settings_status_term, R.string.match_settings_status_location};
            } else {
                if (z || !z2 || !z3) {
                    MatchSettingsFragment matchSettingsFragment = (MatchSettingsFragment) aVarW.c;
                    if (matchSettingsFragment != null) {
                        O6.a(matchSettingsFragment, R.string.match_settings_status_error, null, 2);
                        return;
                    } else {
                        Intrinsics.m("view");
                        throw null;
                    }
                }
                iArr = new int[]{R.string.match_settings_status_definition, R.string.match_settings_status_location};
            }
            i = R.string.match_settings_status_with_two_selected;
        }
        MatchSettingsFragment matchSettingsFragment2 = (MatchSettingsFragment) aVarW.c;
        if (matchSettingsFragment2 != null) {
            O6.a(matchSettingsFragment2, i, Arrays.copyOf(iArr, iArr.length), 4);
        } else {
            Intrinsics.m("view");
            throw null;
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Bundle bundleRequireArguments = requireArguments();
        Parcelable parcelable = bundleRequireArguments.getParcelable("currentSettings");
        if (parcelable == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        MatchSettingsData initialSettings = (MatchSettingsData) parcelable;
        Object availableTermSides = bundleRequireArguments.getIntegerArrayList("availableTermSides");
        if (availableTermSides == null) {
            availableTermSides = K.a;
        }
        boolean z = bundleRequireArguments.getBoolean("isMatchRunning");
        Parcelable parcelable2 = bundleRequireArguments.getParcelable("studyEventLogData");
        if (parcelable2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        StudyEventLogData studyEventLogData = (StudyEventLogData) parcelable2;
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.a aVarW = W();
        Intrinsics.checkNotNullParameter(this, "view");
        Intrinsics.checkNotNullParameter(initialSettings, "initialSettings");
        Intrinsics.checkNotNullParameter(availableTermSides, "availableTermSides");
        Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
        aVarW.c = this;
        aVarW.d = initialSettings;
        aVarW.e = availableTermSides;
        aVarW.a = z;
        aVarW.f = studyEventLogData;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.a aVarW = W();
        StudyModeEventLogger studyModeEventLogger = (StudyModeEventLogger) ((u) aVarW.g).getValue();
        StudyEventLogData studyEventLogData = (StudyEventLogData) aVarW.f;
        if (studyEventLogData == null) {
            Intrinsics.m("studyEventLogData");
            throw null;
        }
        G1 g1 = G1.SET;
        StudyEventLogData studyEventLogData2 = (StudyEventLogData) aVarW.f;
        if (studyEventLogData2 == null) {
            Intrinsics.m("studyEventLogData");
            throw null;
        }
        Long lValueOf = Long.valueOf(studyEventLogData2.b);
        StudyEventLogData studyEventLogData3 = (StudyEventLogData) aVarW.f;
        if (studyEventLogData3 == null) {
            Intrinsics.m("studyEventLogData");
            throw null;
        }
        Long lValueOf2 = Long.valueOf(studyEventLogData3.c);
        StudyEventLogData studyEventLogData4 = (StudyEventLogData) aVarW.f;
        if (studyEventLogData4 == null) {
            Intrinsics.m("studyEventLogData");
            throw null;
        }
        studyModeEventLogger.e(studyEventLogData.a, g1, 1, null, lValueOf, lValueOf2, Boolean.valueOf(studyEventLogData4.d), "settings", null);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStop() {
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.a aVarW = W();
        StudyModeEventLogger studyModeEventLogger = (StudyModeEventLogger) ((u) aVarW.g).getValue();
        StudyEventLogData studyEventLogData = (StudyEventLogData) aVarW.f;
        if (studyEventLogData == null) {
            Intrinsics.m("studyEventLogData");
            throw null;
        }
        G1 g1 = G1.SET;
        StudyEventLogData studyEventLogData2 = (StudyEventLogData) aVarW.f;
        if (studyEventLogData2 == null) {
            Intrinsics.m("studyEventLogData");
            throw null;
        }
        Long lValueOf = Long.valueOf(studyEventLogData2.b);
        StudyEventLogData studyEventLogData3 = (StudyEventLogData) aVarW.f;
        if (studyEventLogData3 == null) {
            Intrinsics.m("studyEventLogData");
            throw null;
        }
        Long lValueOf2 = Long.valueOf(studyEventLogData3.c);
        StudyEventLogData studyEventLogData4 = (StudyEventLogData) aVarW.f;
        if (studyEventLogData4 == null) {
            Intrinsics.m("studyEventLogData");
            throw null;
        }
        studyModeEventLogger.f(studyEventLogData.a, g1, 1, null, lValueOf, lValueOf2, Boolean.valueOf(studyEventLogData4.d), "settings");
        super.onStop();
    }

    /* JADX WARN: Type inference failed for: r1v5, types: [java.lang.Iterable, java.lang.Object] */
    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) throws Resources.NotFoundException {
        O1 o1;
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        int i = requireArguments().getInt("selectedTermCount");
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.a aVarW = W();
        MatchSettingsFragment matchSettingsFragment = (MatchSettingsFragment) aVarW.c;
        if (matchSettingsFragment == null) {
            Intrinsics.m("view");
            throw null;
        }
        boolean z = i > 0;
        LinearLayout matchSettingsGeneralGroup = ((O) matchSettingsFragment.J()).d;
        Intrinsics.checkNotNullExpressionValue(matchSettingsGeneralGroup, "matchSettingsGeneralGroup");
        matchSettingsGeneralGroup.setVisibility(z ? 0 : 8);
        ?? r1 = aVarW.e;
        if (r1 == 0) {
            Intrinsics.m("availableTermSides");
            throw null;
        }
        Iterator it2 = r1.iterator();
        while (it2.hasNext()) {
            int iIntValue = ((Number) it2.next()).intValue();
            O1.Companion.getClass();
            O1[] o1ArrValues = O1.values();
            int length = o1ArrValues.length;
            int i2 = 0;
            while (true) {
                if (i2 >= length) {
                    o1 = null;
                    break;
                }
                o1 = o1ArrValues[i2];
                if (o1.a() == iIntValue) {
                    break;
                } else {
                    i2++;
                }
            }
            int i3 = o1 == null ? -1 : d.a[o1.ordinal()];
            if (i3 == 1) {
                MatchSettingsFragment matchSettingsFragment2 = (MatchSettingsFragment) aVarW.c;
                if (matchSettingsFragment2 == null) {
                    Intrinsics.m("view");
                    throw null;
                }
                RelativeLayout matchSettingsTermSwitchLayout = ((O) matchSettingsFragment2.J()).m;
                Intrinsics.checkNotNullExpressionValue(matchSettingsTermSwitchLayout, "matchSettingsTermSwitchLayout");
                matchSettingsTermSwitchLayout.setVisibility(0);
            } else if (i3 == 2) {
                MatchSettingsFragment matchSettingsFragment3 = (MatchSettingsFragment) aVarW.c;
                if (matchSettingsFragment3 == null) {
                    Intrinsics.m("view");
                    throw null;
                }
                RelativeLayout matchSettingsDefinitionSwitchLayout = ((O) matchSettingsFragment3.J()).c;
                Intrinsics.checkNotNullExpressionValue(matchSettingsDefinitionSwitchLayout, "matchSettingsDefinitionSwitchLayout");
                matchSettingsDefinitionSwitchLayout.setVisibility(0);
            } else if (i3 == 3) {
                MatchSettingsFragment matchSettingsFragment4 = (MatchSettingsFragment) aVarW.c;
                if (matchSettingsFragment4 == null) {
                    Intrinsics.m("view");
                    throw null;
                }
                RelativeLayout matchSettingsLocationSwitchLayout = ((O) matchSettingsFragment4.J()).f;
                Intrinsics.checkNotNullExpressionValue(matchSettingsLocationSwitchLayout, "matchSettingsLocationSwitchLayout");
                matchSettingsLocationSwitchLayout.setVisibility(0);
            } else {
                continue;
            }
        }
        MatchSettingsFragment matchSettingsFragment5 = (MatchSettingsFragment) aVarW.c;
        if (matchSettingsFragment5 == null) {
            Intrinsics.m("view");
            throw null;
        }
        boolean z2 = aVarW.a;
        RelativeLayout matchSettingsRestartMatchButton = ((O) matchSettingsFragment5.J()).i;
        Intrinsics.checkNotNullExpressionValue(matchSettingsRestartMatchButton, "matchSettingsRestartMatchButton");
        matchSettingsRestartMatchButton.setEnabled(z2);
        QTextView matchSettingsRestartMatchButtonText = ((O) matchSettingsFragment5.J()).j;
        Intrinsics.checkNotNullExpressionValue(matchSettingsRestartMatchButtonText, "matchSettingsRestartMatchButtonText");
        matchSettingsRestartMatchButtonText.setEnabled(z2);
        MatchSettingsData matchSettingsData = (MatchSettingsData) aVarW.d;
        if (matchSettingsData == null) {
            Intrinsics.m("initialSettings");
            throw null;
        }
        MatchSettingsFragment matchSettingsFragment6 = (MatchSettingsFragment) aVarW.c;
        if (matchSettingsFragment6 == null) {
            Intrinsics.m("view");
            throw null;
        }
        QSegmentedControl matchSettingsSelectedTermsFilterControl = ((O) matchSettingsFragment6.J()).k;
        Intrinsics.checkNotNullExpressionValue(matchSettingsSelectedTermsFilterControl, "matchSettingsSelectedTermsFilterControl");
        matchSettingsSelectedTermsFilterControl.setCheckedSegment(matchSettingsData.a ? i.c : i.a);
        MatchSettingsFragment matchSettingsFragment7 = (MatchSettingsFragment) aVarW.c;
        if (matchSettingsFragment7 == null) {
            Intrinsics.m("view");
            throw null;
        }
        matchSettingsFragment7.X().setChecked(matchSettingsData.b);
        matchSettingsFragment7.U().setChecked(matchSettingsData.c);
        matchSettingsFragment7.V().setChecked(matchSettingsData.d);
        QSegmentedControl matchSettingsSelectedTermsFilterControl2 = ((O) J()).k;
        Intrinsics.checkNotNullExpressionValue(matchSettingsSelectedTermsFilterControl2, "matchSettingsSelectedTermsFilterControl");
        matchSettingsSelectedTermsFilterControl2.setRightButtonText(getResources().getQuantityString(R.plurals.study_selected_terms, i, Integer.valueOf(i)));
        RelativeLayout matchSettingsRestartMatchButton2 = ((O) J()).i;
        Intrinsics.checkNotNullExpressionValue(matchSettingsRestartMatchButton2, "matchSettingsRestartMatchButton");
        matchSettingsRestartMatchButton2.setOnClickListener(new h(this, 17));
        final int i4 = 0;
        X().setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.settings.b
            public final /* synthetic */ MatchSettingsFragment b;

            {
                this.b = this;
            }

            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z3) {
                MatchSettingsFragment matchSettingsFragment8 = this.b;
                switch (i4) {
                    case 0:
                        String str = MatchSettingsFragment.k;
                        matchSettingsFragment8.a0();
                        break;
                    case 1:
                        String str2 = MatchSettingsFragment.k;
                        matchSettingsFragment8.a0();
                        break;
                    default:
                        String str3 = MatchSettingsFragment.k;
                        matchSettingsFragment8.a0();
                        break;
                }
            }
        });
        final int i5 = 1;
        U().setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.settings.b
            public final /* synthetic */ MatchSettingsFragment b;

            {
                this.b = this;
            }

            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z3) {
                MatchSettingsFragment matchSettingsFragment8 = this.b;
                switch (i5) {
                    case 0:
                        String str = MatchSettingsFragment.k;
                        matchSettingsFragment8.a0();
                        break;
                    case 1:
                        String str2 = MatchSettingsFragment.k;
                        matchSettingsFragment8.a0();
                        break;
                    default:
                        String str3 = MatchSettingsFragment.k;
                        matchSettingsFragment8.a0();
                        break;
                }
            }
        });
        final int i6 = 2;
        V().setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.settings.b
            public final /* synthetic */ MatchSettingsFragment b;

            {
                this.b = this;
            }

            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z3) {
                MatchSettingsFragment matchSettingsFragment8 = this.b;
                switch (i6) {
                    case 0:
                        String str = MatchSettingsFragment.k;
                        matchSettingsFragment8.a0();
                        break;
                    case 1:
                        String str2 = MatchSettingsFragment.k;
                        matchSettingsFragment8.a0();
                        break;
                    default:
                        String str3 = MatchSettingsFragment.k;
                        matchSettingsFragment8.a0();
                        break;
                }
            }
        });
        a0();
    }
}
