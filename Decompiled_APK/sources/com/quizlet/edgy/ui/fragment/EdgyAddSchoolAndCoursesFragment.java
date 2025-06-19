package com.quizlet.edgy.ui.fragment;

import android.content.res.Resources;
import android.os.Bundle;
import android.text.Editable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.lifecycle.p0;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.C1370i;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.input.AssemblyInputEditText;
import com.quizlet.assembly.widgets.input.AssemblyInputLayout;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class EdgyAddSchoolAndCoursesFragment extends Hilt_EdgyAddSchoolAndCoursesFragment<com.quizlet.edgy.databinding.b> {
    public static final String u;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(com.quizlet.edgy.ui.viewmodel.M.class), new r(this, 0), new r(this, 2), new r(this, 1));
    public final kotlin.u k = kotlin.l.b(new com.quizlet.db.data.models.persisted.types.a(16));
    public final kotlin.u l = kotlin.l.b(new C4192f(this, 4));
    public final kotlin.u m = kotlin.l.b(new C4192f(this, 5));
    public final kotlin.u n = kotlin.l.b(new C4192f(this, 6));
    public final kotlin.u o = kotlin.l.b(new C4192f(this, 7));
    public final kotlin.u p = kotlin.l.b(new C4192f(this, 8));
    public final kotlin.u q = kotlin.l.b(new C4192f(this, 9));
    public final kotlin.u r = kotlin.l.b(new C4192f(this, 10));
    public final kotlin.u s = kotlin.l.b(new C4192f(this, 11));
    public final kotlin.u t = kotlin.l.b(new C4192f(this, 0));

    static {
        Intrinsics.checkNotNullExpressionValue("EdgyAddSchoolAndCoursesFragment", "getSimpleName(...)");
        u = "EdgyAddSchoolAndCoursesFragment";
    }

    public static final void T(EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment, com.quizlet.edgy.ui.viewmodel.r rVar) {
        AbstractC1361d0 abstractC1361d0;
        com.quizlet.edgy.databinding.b bVar = (com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment.J();
        AssemblyInputLayout searchSchoolInputLayout = bVar.i;
        Intrinsics.checkNotNullExpressionValue(searchSchoolInputLayout, "searchSchoolInputLayout");
        searchSchoolInputLayout.setVisibility(rVar.a ? 0 : 8);
        TextView emptyResultsText = bVar.c;
        Intrinsics.checkNotNullExpressionValue(emptyResultsText, "emptyResultsText");
        emptyResultsText.setVisibility(rVar.b ? 0 : 8);
        bVar.h.setEnabled(rVar.c);
        AssemblyInputLayout searchCourseInputLayout = bVar.g;
        Intrinsics.checkNotNullExpressionValue(searchCourseInputLayout, "searchCourseInputLayout");
        searchCourseInputLayout.setVisibility(rVar.d ? 0 : 8);
        ProgressBar loading = bVar.d;
        Intrinsics.checkNotNullExpressionValue(loading, "loading");
        loading.setVisibility(rVar.e ? 0 : 8);
        AssemblyPrimaryButton btnDone = bVar.b;
        Intrinsics.checkNotNullExpressionValue(btnDone, "btnDone");
        btnDone.setVisibility(rVar.l ? 0 : 8);
        com.quizlet.edgy.databinding.b bVar2 = (com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment.J();
        if (rVar.g) {
            bVar2.h.setText(R.string.empty);
        }
        if (rVar.h) {
            bVar2.f.setText(R.string.empty);
        }
        com.quizlet.edgy.databinding.b bVar3 = (com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment.J();
        if (rVar.i) {
            bVar3.h.requestFocus();
        }
        if (rVar.j) {
            bVar3.f.requestFocus();
        }
        com.quizlet.edgy.databinding.b bVar4 = (com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment.J();
        switch (rVar.f.ordinal()) {
            case 0:
                abstractC1361d0 = null;
                break;
            case 1:
                abstractC1361d0 = (C1370i) edgyAddSchoolAndCoursesFragment.s.getValue();
                break;
            case 2:
                abstractC1361d0 = (com.quizlet.edgy.ui.recyclerview.adapter.b) edgyAddSchoolAndCoursesFragment.o.getValue();
                break;
            case 3:
                abstractC1361d0 = (com.quizlet.edgy.ui.recyclerview.adapter.a) edgyAddSchoolAndCoursesFragment.p.getValue();
                break;
            case 4:
                abstractC1361d0 = (C1370i) edgyAddSchoolAndCoursesFragment.q.getValue();
                break;
            case 5:
                abstractC1361d0 = (C1370i) edgyAddSchoolAndCoursesFragment.r.getValue();
                break;
            case 6:
                abstractC1361d0 = (com.quizlet.edgy.ui.recyclerview.adapter.c) edgyAddSchoolAndCoursesFragment.n.getValue();
                break;
            case 7:
                abstractC1361d0 = (com.quizlet.edgy.ui.recyclerview.adapter.f) edgyAddSchoolAndCoursesFragment.m.getValue();
                break;
            default:
                throw new NoWhenBranchMatchedException();
        }
        bVar4.e.setAdapter(abstractC1361d0);
        RecyclerView recyclerView = ((com.quizlet.edgy.databinding.b) edgyAddSchoolAndCoursesFragment.J()).e;
        kotlin.u uVar = edgyAddSchoolAndCoursesFragment.t;
        boolean z = rVar.k;
        if (z && recyclerView.getItemDecorationCount() == 0) {
            recyclerView.i((com.quizlet.baserecyclerview.decoration.c) uVar.getValue());
        } else {
            if (z || recyclerView.getItemDecorationCount() != 1) {
                return;
            }
            recyclerView.g0((com.quizlet.baserecyclerview.decoration.c) uVar.getValue());
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return u;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_add_school_and_courses, viewGroup, false);
        int i = R.id.btnDone;
        AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.btnDone, viewInflate);
        if (assemblyPrimaryButton != null) {
            i = R.id.emptyResultsText;
            TextView textView = (TextView) AbstractC3375o2.c(R.id.emptyResultsText, viewInflate);
            if (textView != null) {
                i = R.id.loading;
                ProgressBar progressBar = (ProgressBar) AbstractC3375o2.c(R.id.loading, viewInflate);
                if (progressBar != null) {
                    i = R.id.recyclerView;
                    RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.recyclerView, viewInflate);
                    if (recyclerView != null) {
                        i = R.id.searchCourseEditText;
                        AssemblyInputEditText assemblyInputEditText = (AssemblyInputEditText) AbstractC3375o2.c(R.id.searchCourseEditText, viewInflate);
                        if (assemblyInputEditText != null) {
                            i = R.id.searchCourseInputLayout;
                            AssemblyInputLayout assemblyInputLayout = (AssemblyInputLayout) AbstractC3375o2.c(R.id.searchCourseInputLayout, viewInflate);
                            if (assemblyInputLayout != null) {
                                i = R.id.searchSchoolEditText;
                                AssemblyInputEditText assemblyInputEditText2 = (AssemblyInputEditText) AbstractC3375o2.c(R.id.searchSchoolEditText, viewInflate);
                                if (assemblyInputEditText2 != null) {
                                    i = R.id.searchSchoolInputLayout;
                                    AssemblyInputLayout assemblyInputLayout2 = (AssemblyInputLayout) AbstractC3375o2.c(R.id.searchSchoolInputLayout, viewInflate);
                                    if (assemblyInputLayout2 != null) {
                                        com.quizlet.edgy.databinding.b bVar = new com.quizlet.edgy.databinding.b((ConstraintLayout) viewInflate, assemblyPrimaryButton, textView, progressBar, recyclerView, assemblyInputEditText, assemblyInputLayout, assemblyInputEditText2, assemblyInputLayout2);
                                        Intrinsics.checkNotNullExpressionValue(bVar, "inflate(...)");
                                        return bVar;
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

    public final com.quizlet.edgy.ui.viewmodel.M U() {
        return (com.quizlet.edgy.ui.viewmodel.M) this.j.getValue();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        final com.quizlet.edgy.databinding.b bVar = (com.quizlet.edgy.databinding.b) J();
        com.google.android.material.textfield.a aVar = new com.google.android.material.textfield.a(this, 2);
        AssemblyInputEditText searchSchoolEditText = bVar.h;
        searchSchoolEditText.setOnFocusChangeListener(aVar);
        final int i = 0;
        searchSchoolEditText.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.edgy.ui.fragment.g
            public final /* synthetic */ EdgyAddSchoolAndCoursesFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment = this.b;
                switch (i) {
                    case 0:
                        String str = EdgyAddSchoolAndCoursesFragment.u;
                        edgyAddSchoolAndCoursesFragment.U().F(false);
                        break;
                    default:
                        String str2 = EdgyAddSchoolAndCoursesFragment.u;
                        com.quizlet.edgy.ui.viewmodel.M mU = edgyAddSchoolAndCoursesFragment.U();
                        mU.j.j("edgy_data_final_cta_clicked", "submit", "edgy_data", true);
                        kotlinx.coroutines.E.A(p0.j(mU), null, null, new com.quizlet.edgy.ui.viewmodel.z(mU, null), 3);
                        break;
                }
            }
        });
        Intrinsics.checkNotNullExpressionValue(searchSchoolEditText, "searchSchoolEditText");
        searchSchoolEditText.addTextChangedListener(new C4197k(bVar, this, i));
        final int i2 = 0;
        bVar.i.setEndIconOnClickListener(new View.OnClickListener() { // from class: com.quizlet.edgy.ui.fragment.h
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment = this;
                com.quizlet.edgy.databinding.b bVar2 = bVar;
                switch (i2) {
                    case 0:
                        String str = EdgyAddSchoolAndCoursesFragment.u;
                        Editable text = bVar2.h.getText();
                        if (text != null && text.length() != 0) {
                            com.quizlet.edgy.ui.viewmodel.M mU = edgyAddSchoolAndCoursesFragment.U();
                            if (!mU.o.isEmpty()) {
                                kotlinx.coroutines.E.A(p0.j(mU), null, null, new com.quizlet.edgy.ui.viewmodel.F(mU, null), 3);
                                break;
                            } else {
                                mU.C();
                                break;
                            }
                        }
                        break;
                    default:
                        String str2 = EdgyAddSchoolAndCoursesFragment.u;
                        AssemblyInputEditText assemblyInputEditText = bVar2.f;
                        Editable text2 = assemblyInputEditText.getText();
                        if (text2 != null && text2.length() != 0) {
                            assemblyInputEditText.setText((CharSequence) null);
                            edgyAddSchoolAndCoursesFragment.U().D();
                            break;
                        }
                        break;
                }
            }
        });
        AssemblyInputEditText searchCourseEditText = bVar.f;
        Intrinsics.checkNotNullExpressionValue(searchCourseEditText, "searchCourseEditText");
        searchCourseEditText.addTextChangedListener(new C4197k(bVar, this, 1));
        final int i3 = 1;
        bVar.g.setEndIconOnClickListener(new View.OnClickListener() { // from class: com.quizlet.edgy.ui.fragment.h
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment = this;
                com.quizlet.edgy.databinding.b bVar2 = bVar;
                switch (i3) {
                    case 0:
                        String str = EdgyAddSchoolAndCoursesFragment.u;
                        Editable text = bVar2.h.getText();
                        if (text != null && text.length() != 0) {
                            com.quizlet.edgy.ui.viewmodel.M mU = edgyAddSchoolAndCoursesFragment.U();
                            if (!mU.o.isEmpty()) {
                                kotlinx.coroutines.E.A(p0.j(mU), null, null, new com.quizlet.edgy.ui.viewmodel.F(mU, null), 3);
                                break;
                            } else {
                                mU.C();
                                break;
                            }
                        }
                        break;
                    default:
                        String str2 = EdgyAddSchoolAndCoursesFragment.u;
                        AssemblyInputEditText assemblyInputEditText = bVar2.f;
                        Editable text2 = assemblyInputEditText.getText();
                        if (text2 != null && text2.length() != 0) {
                            assemblyInputEditText.setText((CharSequence) null);
                            edgyAddSchoolAndCoursesFragment.U().D();
                            break;
                        }
                        break;
                }
            }
        });
        final int i4 = 1;
        bVar.b.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.edgy.ui.fragment.g
            public final /* synthetic */ EdgyAddSchoolAndCoursesFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment = this.b;
                switch (i4) {
                    case 0:
                        String str = EdgyAddSchoolAndCoursesFragment.u;
                        edgyAddSchoolAndCoursesFragment.U().F(false);
                        break;
                    default:
                        String str2 = EdgyAddSchoolAndCoursesFragment.u;
                        com.quizlet.edgy.ui.viewmodel.M mU = edgyAddSchoolAndCoursesFragment.U();
                        mU.j.j("edgy_data_final_cta_clicked", "submit", "edgy_data", true);
                        kotlinx.coroutines.E.A(p0.j(mU), null, null, new com.quizlet.edgy.ui.viewmodel.z(mU, null), 3);
                        break;
                }
            }
        });
        androidx.lifecycle.J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        kotlinx.coroutines.E.A(p0.h(viewLifecycleOwner), null, null, new n(this, null), 3);
        androidx.lifecycle.J viewLifecycleOwner2 = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner2, "getViewLifecycleOwner(...)");
        kotlinx.coroutines.E.A(p0.h(viewLifecycleOwner2), null, null, new q(this, null), 3);
        com.quizlet.edgy.databinding.b bVar2 = (com.quizlet.edgy.databinding.b) J();
        bVar2.i.setEndIconVisible(false);
        bVar2.g.setEndIconVisible(false);
    }
}
