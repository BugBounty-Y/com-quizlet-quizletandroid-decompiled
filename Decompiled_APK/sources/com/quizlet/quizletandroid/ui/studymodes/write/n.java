package com.quizlet.quizletandroid.ui.studymodes.write;

import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.toggle.AssemblyToggleSwitch;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.generated.enums.O1;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.p0;
import com.quizlet.uicommon.ui.common.widgets.QSegmentedControl;

/* loaded from: classes3.dex */
public abstract class n extends BaseFragment {
    public int e;
    public boolean f;
    public String g;
    public String h;
    public com.quizlet.quizletandroid.util.f i;

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return "WriteSettingsFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater layoutInflater, ViewGroup viewGroup) {
        View viewInflate = layoutInflater.inflate(R.layout.write_settings, viewGroup, false);
        int i = R.id.audio_on_toggle;
        AssemblyToggleSwitch assemblyToggleSwitch = (AssemblyToggleSwitch) AbstractC3375o2.c(R.id.audio_on_toggle, viewInflate);
        if (assemblyToggleSwitch != null) {
            i = R.id.image_options_section;
            LinearLayout linearLayout = (LinearLayout) AbstractC3375o2.c(R.id.image_options_section, viewInflate);
            if (linearLayout != null) {
                i = R.id.selected_filter_control;
                QSegmentedControl qSegmentedControl = (QSegmentedControl) AbstractC3375o2.c(R.id.selected_filter_control, viewInflate);
                if (qSegmentedControl != null) {
                    i = R.id.selected_filter_group;
                    FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.selected_filter_group, viewInflate);
                    if (frameLayout != null) {
                        i = R.id.show_image_toggle;
                        AssemblyToggleSwitch assemblyToggleSwitch2 = (AssemblyToggleSwitch) AbstractC3375o2.c(R.id.show_image_toggle, viewInflate);
                        if (assemblyToggleSwitch2 != null) {
                            i = R.id.start_over;
                            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.start_over, viewInflate);
                            if (qTextView != null) {
                                i = R.id.start_with_term_label;
                                QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.start_with_term_label, viewInflate);
                                if (qTextView2 != null) {
                                    i = R.id.start_with_term_toggle;
                                    AssemblyToggleSwitch assemblyToggleSwitch3 = (AssemblyToggleSwitch) AbstractC3375o2.c(R.id.start_with_term_toggle, viewInflate);
                                    if (assemblyToggleSwitch3 != null) {
                                        i = R.id.type_answer_toggle;
                                        AssemblyToggleSwitch assemblyToggleSwitch4 = (AssemblyToggleSwitch) AbstractC3375o2.c(R.id.type_answer_toggle, viewInflate);
                                        if (assemblyToggleSwitch4 != null) {
                                            return new p0((ScrollView) viewInflate, assemblyToggleSwitch, linearLayout, qSegmentedControl, frameLayout, assemblyToggleSwitch2, qTextView, qTextView2, assemblyToggleSwitch3, assemblyToggleSwitch4);
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

    public final WriteStudyModeConfig Q() {
        return new WriteStudyModeConfig(((p0) J()).i.isChecked() ? O1.WORD : O1.DEFINITION, ((p0) J()).j.isChecked(), ((p0) J()).b.isChecked(), ((p0) J()).f.isChecked(), ((p0) J()).d.getCheckedSegment() == com.quizlet.uicommon.ui.common.widgets.i.c);
    }

    public final void R(boolean z) {
        Intent intent = new Intent();
        intent.putExtra("learnModeConfig", Q());
        intent.putExtra("learnModeRestart", z);
        getActivity().setResult(-1, intent);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Bundle arguments = getArguments();
        this.e = arguments.getInt("selectedTermCount");
        this.f = arguments.getBoolean("showImageOptions");
        this.g = arguments.getString("studyableWordLanguageCode");
        this.h = arguments.getString("studyableDefinitionLanguageCode");
    }

    @Override // androidx.fragment.app.Fragment
    public final boolean onOptionsItemSelected(MenuItem menuItem) {
        if (menuItem.getItemId() == 16908332) {
            R(false);
        }
        return super.onOptionsItemSelected(menuItem);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle bundle) {
        bundle.putParcelable("learnModeConfig", Q());
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x005c  */
    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onViewCreated(android.view.View r9, android.os.Bundle r10) throws android.content.res.Resources.NotFoundException {
        /*
            Method dump skipped, instructions count: 317
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.write.n.onViewCreated(android.view.View, android.os.Bundle):void");
    }
}
