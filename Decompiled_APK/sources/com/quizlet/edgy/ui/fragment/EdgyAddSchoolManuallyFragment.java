package com.quizlet.edgy.ui.fragment;

import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.ScrollView;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.onetrust.otpublishers.headless.Public.OTCCPAGeolocationConstants;
import com.onetrust.otpublishers.headless.UI.fragment.C4062f;
import com.quizlet.assembly.widgets.input.AssemblyInputEditText;
import com.quizlet.assembly.widgets.input.AssemblyInputLayout;
import com.quizlet.edgy.model.Country;
import com.quizlet.edgy.model.State;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.R;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes2.dex */
public final class EdgyAddSchoolManuallyFragment extends Hilt_EdgyAddSchoolManuallyFragment<com.quizlet.edgy.databinding.c> {
    public static final String o;
    public com.quizlet.edgy.utils.d j;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e k;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e l;
    public ArrayAdapter m;
    public ArrayAdapter n;

    static {
        Intrinsics.checkNotNullExpressionValue("EdgyAddSchoolManuallyFragment", "getSimpleName(...)");
        o = "EdgyAddSchoolManuallyFragment";
    }

    public EdgyAddSchoolManuallyFragment() {
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new assistantMode.experiments.a(new assistantMode.experiments.a(this, 9), 10));
        this.k = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(com.quizlet.edgy.ui.viewmodel.w.class), new C4062f(kVarA, 8), new androidx.credentials.playservices.controllers.BeginSignIn.d(18, this, kVarA), new C4062f(kVarA, 9));
        this.l = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(com.quizlet.edgy.ui.viewmodel.M.class), new G(this, 0), new G(this, 2), new G(this, 1));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return o;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_add_school_manually, viewGroup, false);
        int i = R.id.btnSaveSchool;
        QButton qButton = (QButton) AbstractC3375o2.c(R.id.btnSaveSchool, viewInflate);
        if (qButton != null) {
            i = R.id.cityEditText;
            AssemblyInputEditText assemblyInputEditText = (AssemblyInputEditText) AbstractC3375o2.c(R.id.cityEditText, viewInflate);
            if (assemblyInputEditText != null) {
                i = R.id.cityInputLayout;
                if (((AssemblyInputLayout) AbstractC3375o2.c(R.id.cityInputLayout, viewInflate)) != null) {
                    i = R.id.countryAutoComplete;
                    AutoCompleteTextView autoCompleteTextView = (AutoCompleteTextView) AbstractC3375o2.c(R.id.countryAutoComplete, viewInflate);
                    if (autoCompleteTextView != null) {
                        i = R.id.countryDropdown;
                        if (((AssemblyInputLayout) AbstractC3375o2.c(R.id.countryDropdown, viewInflate)) != null) {
                            i = R.id.schoolNameEditText;
                            AssemblyInputEditText assemblyInputEditText2 = (AssemblyInputEditText) AbstractC3375o2.c(R.id.schoolNameEditText, viewInflate);
                            if (assemblyInputEditText2 != null) {
                                i = R.id.schoolNameInputLayout;
                                if (((AssemblyInputLayout) AbstractC3375o2.c(R.id.schoolNameInputLayout, viewInflate)) != null) {
                                    i = R.id.stateAutoComplete;
                                    AutoCompleteTextView autoCompleteTextView2 = (AutoCompleteTextView) AbstractC3375o2.c(R.id.stateAutoComplete, viewInflate);
                                    if (autoCompleteTextView2 != null) {
                                        i = R.id.stateDropdown;
                                        AssemblyInputLayout assemblyInputLayout = (AssemblyInputLayout) AbstractC3375o2.c(R.id.stateDropdown, viewInflate);
                                        if (assemblyInputLayout != null) {
                                            com.quizlet.edgy.databinding.c cVar = new com.quizlet.edgy.databinding.c((ScrollView) viewInflate, qButton, assemblyInputEditText, autoCompleteTextView, assemblyInputEditText2, autoCompleteTextView2, assemblyInputLayout);
                                            Intrinsics.checkNotNullExpressionValue(cVar, "inflate(...)");
                                            return cVar;
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

    public final com.quizlet.edgy.utils.d T() {
        com.quizlet.edgy.utils.d dVar = this.j;
        if (dVar != null) {
            return dVar;
        }
        Intrinsics.m("emptyFieldValidationTextWatcher");
        throw null;
    }

    public final com.quizlet.edgy.ui.viewmodel.w U() {
        return (com.quizlet.edgy.ui.viewmodel.w) this.k.getValue();
    }

    public final void V(boolean z) {
        List listJ;
        com.quizlet.edgy.utils.d dVarT = T();
        if (z) {
            com.quizlet.edgy.databinding.c cVar = (com.quizlet.edgy.databinding.c) J();
            com.quizlet.edgy.databinding.c cVar2 = (com.quizlet.edgy.databinding.c) J();
            listJ = kotlin.collections.B.j(cVar.e, cVar2.c, ((com.quizlet.edgy.databinding.c) J()).f);
        } else {
            listJ = kotlin.collections.B.j(((com.quizlet.edgy.databinding.c) J()).e, ((com.quizlet.edgy.databinding.c) J()).c);
        }
        dVarT.c = listJ;
        dVarT.e();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        T().b = ((com.quizlet.edgy.databinding.c) J()).b;
        V(true);
        androidx.lifecycle.J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        kotlinx.coroutines.E.A(p0.h(viewLifecycleOwner), null, null, new w(this, null), 3);
        androidx.lifecycle.J viewLifecycleOwner2 = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner2, "getViewLifecycleOwner(...)");
        kotlinx.coroutines.E.A(p0.h(viewLifecycleOwner2), null, null, new z(this, null), 3);
        androidx.lifecycle.J viewLifecycleOwner3 = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner3, "getViewLifecycleOwner(...)");
        kotlinx.coroutines.E.A(p0.h(viewLifecycleOwner3), null, null, new C(this, null), 3);
        androidx.lifecycle.J viewLifecycleOwner4 = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner4, "getViewLifecycleOwner(...)");
        kotlinx.coroutines.E.A(p0.h(viewLifecycleOwner4), null, null, new F(this, null), 3);
        com.quizlet.edgy.databinding.c cVar = (com.quizlet.edgy.databinding.c) J();
        cVar.d.setDropDownBackgroundDrawable(new ColorDrawable(0));
        com.quizlet.edgy.databinding.c cVar2 = (com.quizlet.edgy.databinding.c) J();
        cVar2.f.setDropDownBackgroundDrawable(new ColorDrawable(0));
        com.quizlet.edgy.databinding.c cVar3 = (com.quizlet.edgy.databinding.c) J();
        final int i = 0;
        cVar3.d.setOnItemClickListener(new AdapterView.OnItemClickListener(this) { // from class: com.quizlet.edgy.ui.fragment.t
            public final /* synthetic */ EdgyAddSchoolManuallyFragment b;

            {
                this.b = this;
            }

            @Override // android.widget.AdapterView.OnItemClickListener
            public final void onItemClick(AdapterView adapterView, View view2, int i2, long j) {
                Object value;
                Object value2;
                Object obj = null;
                EdgyAddSchoolManuallyFragment edgyAddSchoolManuallyFragment = this.b;
                switch (i) {
                    case 0:
                        String str = EdgyAddSchoolManuallyFragment.o;
                        com.quizlet.edgy.ui.viewmodel.w wVarU = edgyAddSchoolManuallyFragment.U();
                        ArrayAdapter arrayAdapter = edgyAddSchoolManuallyFragment.m;
                        String countryName = String.valueOf(arrayAdapter != null ? (String) arrayAdapter.getItem(i2) : null);
                        wVarU.getClass();
                        Intrinsics.checkNotNullParameter(countryName, "countryName");
                        for (Country country : (Iterable) wVarU.f.getValue()) {
                            if (Intrinsics.b(country.b, countryName)) {
                                wVarU.d = country;
                                boolean zB = Intrinsics.b(country.a, OTCCPAGeolocationConstants.US);
                                s0 s0Var = wVarU.h;
                                if (zB) {
                                    do {
                                        value2 = s0Var.getValue();
                                        ((Boolean) value2).getClass();
                                    } while (!s0Var.k(value2, Boolean.TRUE));
                                    return;
                                } else {
                                    do {
                                        value = s0Var.getValue();
                                        ((Boolean) value).getClass();
                                    } while (!s0Var.k(value, Boolean.FALSE));
                                    wVarU.e = null;
                                    return;
                                }
                            }
                        }
                        throw new NoSuchElementException("Collection contains no element matching the predicate.");
                    default:
                        String str2 = EdgyAddSchoolManuallyFragment.o;
                        com.quizlet.edgy.ui.viewmodel.w wVarU2 = edgyAddSchoolManuallyFragment.U();
                        ArrayAdapter arrayAdapter2 = edgyAddSchoolManuallyFragment.n;
                        String stateName = String.valueOf(arrayAdapter2 != null ? (String) arrayAdapter2.getItem(i2) : null);
                        wVarU2.getClass();
                        Intrinsics.checkNotNullParameter(stateName, "stateName");
                        Iterator it2 = ((Iterable) wVarU2.g.getValue()).iterator();
                        while (true) {
                            if (it2.hasNext()) {
                                Object next = it2.next();
                                if (Intrinsics.b(((State) next).b, stateName)) {
                                    obj = next;
                                }
                            }
                        }
                        wVarU2.e = (State) obj;
                        return;
                }
            }
        });
        com.quizlet.edgy.databinding.c cVar4 = (com.quizlet.edgy.databinding.c) J();
        final int i2 = 1;
        cVar4.f.setOnItemClickListener(new AdapterView.OnItemClickListener(this) { // from class: com.quizlet.edgy.ui.fragment.t
            public final /* synthetic */ EdgyAddSchoolManuallyFragment b;

            {
                this.b = this;
            }

            @Override // android.widget.AdapterView.OnItemClickListener
            public final void onItemClick(AdapterView adapterView, View view2, int i22, long j) {
                Object value;
                Object value2;
                Object obj = null;
                EdgyAddSchoolManuallyFragment edgyAddSchoolManuallyFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = EdgyAddSchoolManuallyFragment.o;
                        com.quizlet.edgy.ui.viewmodel.w wVarU = edgyAddSchoolManuallyFragment.U();
                        ArrayAdapter arrayAdapter = edgyAddSchoolManuallyFragment.m;
                        String countryName = String.valueOf(arrayAdapter != null ? (String) arrayAdapter.getItem(i22) : null);
                        wVarU.getClass();
                        Intrinsics.checkNotNullParameter(countryName, "countryName");
                        for (Country country : (Iterable) wVarU.f.getValue()) {
                            if (Intrinsics.b(country.b, countryName)) {
                                wVarU.d = country;
                                boolean zB = Intrinsics.b(country.a, OTCCPAGeolocationConstants.US);
                                s0 s0Var = wVarU.h;
                                if (zB) {
                                    do {
                                        value2 = s0Var.getValue();
                                        ((Boolean) value2).getClass();
                                    } while (!s0Var.k(value2, Boolean.TRUE));
                                    return;
                                } else {
                                    do {
                                        value = s0Var.getValue();
                                        ((Boolean) value).getClass();
                                    } while (!s0Var.k(value, Boolean.FALSE));
                                    wVarU.e = null;
                                    return;
                                }
                            }
                        }
                        throw new NoSuchElementException("Collection contains no element matching the predicate.");
                    default:
                        String str2 = EdgyAddSchoolManuallyFragment.o;
                        com.quizlet.edgy.ui.viewmodel.w wVarU2 = edgyAddSchoolManuallyFragment.U();
                        ArrayAdapter arrayAdapter2 = edgyAddSchoolManuallyFragment.n;
                        String stateName = String.valueOf(arrayAdapter2 != null ? (String) arrayAdapter2.getItem(i22) : null);
                        wVarU2.getClass();
                        Intrinsics.checkNotNullParameter(stateName, "stateName");
                        Iterator it2 = ((Iterable) wVarU2.g.getValue()).iterator();
                        while (true) {
                            if (it2.hasNext()) {
                                Object next = it2.next();
                                if (Intrinsics.b(((State) next).b, stateName)) {
                                    obj = next;
                                }
                            }
                        }
                        wVarU2.e = (State) obj;
                        return;
                }
            }
        });
        com.quizlet.edgy.databinding.c cVar5 = (com.quizlet.edgy.databinding.c) J();
        cVar5.b.setOnClickListener(new com.braze.ui.inappmessage.d(this, 14));
        com.quizlet.edgy.databinding.c cVar6 = (com.quizlet.edgy.databinding.c) J();
        cVar6.e.addTextChangedListener(T());
        com.quizlet.edgy.databinding.c cVar7 = (com.quizlet.edgy.databinding.c) J();
        cVar7.c.addTextChangedListener(T());
        com.quizlet.edgy.databinding.c cVar8 = (com.quizlet.edgy.databinding.c) J();
        cVar8.f.addTextChangedListener(T());
        ((com.quizlet.edgy.databinding.c) J()).d.setText((CharSequence) "United States", false);
    }
}
