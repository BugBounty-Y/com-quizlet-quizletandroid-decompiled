package com.onetrust.otpublishers.headless.UI.fragment;

import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.widget.SearchView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.text.StringsKt__StringsKt;
import org.json.JSONArray;
import org.json.JSONException;

@Metadata
/* loaded from: classes2.dex */
public final class s extends com.google.android.material.bottomsheet.i {
    public com.onetrust.otpublishers.headless.databinding.b q;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e r;
    public OTPublishersHeadlessSDK s;
    public OTConfiguration t;
    public final assistantMode.utils.studiableMetadata.b u;
    public com.google.android.material.bottomsheet.i v;
    public com.onetrust.otpublishers.headless.UI.adapter.r w;
    public com.google.android.material.bottomsheet.h x;
    public t y;

    public s() {
        r rVar = new r(this, 1);
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new assistantMode.experiments.a(new r(this, 0), 5));
        this.r = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.onetrust.otpublishers.headless.UI.viewmodel.d.class), new C4062f(kVarA, 2), rVar, new C4062f(kVarA, 3));
        this.u = new assistantMode.utils.studiableMetadata.b(22);
    }

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        Intrinsics.checkNotNullExpressionValue(dialogK, "super.onCreateDialog(savedInstanceState)");
        dialogK.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 8));
        return dialogK;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0089 A[PHI: r0 r1 r7
  0x0089: PHI (r0v5 android.widget.ImageView) = (r0v3 android.widget.ImageView), (r0v6 android.widget.ImageView) binds: [B:38:0x00f2, B:20:0x0087] A[DONT_GENERATE, DONT_INLINE]
  0x0089: PHI (r1v9 java.lang.String) = (r1v8 java.lang.String), (r1v11 java.lang.String) binds: [B:38:0x00f2, B:20:0x0087] A[DONT_GENERATE, DONT_INLINE]
  0x0089: PHI (r7v24 java.lang.String) = (r7v7 java.lang.String), (r7v28 java.lang.String) binds: [B:38:0x00f2, B:20:0x0087] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void Q(java.lang.Boolean r7) {
        /*
            Method dump skipped, instructions count: 253
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.s.Q(java.lang.Boolean):void");
    }

    public final void R(boolean z) {
        com.onetrust.otpublishers.headless.databinding.b bVar = this.q;
        Intrinsics.d(bVar);
        com.onetrust.otpublishers.headless.databinding.f fVar = (com.onetrust.otpublishers.headless.databinding.f) bVar.d;
        SwitchCompat sdkAllowAllToggle = fVar.f;
        Intrinsics.checkNotNullExpressionValue(sdkAllowAllToggle, "sdkAllowAllToggle");
        sdkAllowAllToggle.setVisibility(z ? 0 : 8);
        TextView sdkAllowAllTitle = fVar.e;
        Intrinsics.checkNotNullExpressionValue(sdkAllowAllTitle, "sdkAllowAllTitle");
        sdkAllowAllTitle.setVisibility(z ? 0 : 8);
    }

    public final com.onetrust.otpublishers.headless.UI.viewmodel.d S() {
        return (com.onetrust.otpublishers.headless.UI.viewmodel.d) this.r.getValue();
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [com.google.android.material.bottomsheet.i, com.onetrust.otpublishers.headless.UI.adapter.t] */
    public final void a() throws JSONException {
        G();
        S().q.l(kotlin.collections.K.a);
        com.onetrust.otpublishers.headless.UI.viewmodel.d dVarS = S();
        for (String str : dVarS.o.keySet()) {
            JSONArray it2 = dVarS.l.f(str);
            Intrinsics.checkNotNullExpressionValue(it2, "it");
            int length = it2.length();
            int i = 0;
            int i2 = 0;
            for (int i3 = 0; i3 < length; i3++) {
                String string = it2.get(i3).toString();
                OTPublishersHeadlessSDK oTPublishersHeadlessSDK = dVarS.d;
                if (oTPublishersHeadlessSDK == null || oTPublishersHeadlessSDK.getConsentStatusForSDKId(string) != 0) {
                    OTPublishersHeadlessSDK oTPublishersHeadlessSDK2 = dVarS.d;
                    if (oTPublishersHeadlessSDK2 != null && 1 == oTPublishersHeadlessSDK2.getConsentStatusForSDKId(string) && (i2 = i2 + 1) == it2.length()) {
                        OTPublishersHeadlessSDK oTPublishersHeadlessSDK3 = dVarS.d;
                        if (oTPublishersHeadlessSDK3 != null) {
                            oTPublishersHeadlessSDK3.updatePurposeConsent(str, true, true);
                        }
                        i2 = 0;
                    }
                } else {
                    i++;
                    if (i == it2.length()) {
                        OTPublishersHeadlessSDK oTPublishersHeadlessSDK4 = dVarS.d;
                        if (oTPublishersHeadlessSDK4 != null) {
                            oTPublishersHeadlessSDK4.updatePurposeConsent(str, false, true);
                        }
                        i = 0;
                    }
                }
            }
        }
        ?? r0 = this.v;
        if (r0 != 0) {
            r0.a();
        }
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration newConfig) {
        Intrinsics.checkNotNullParameter(newConfig, "newConfig");
        super.onConfigurationChanged(newConfig);
        androidx.fragment.app.I iRequireActivity = requireActivity();
        com.google.android.material.bottomsheet.h hVar = this.x;
        this.u.getClass();
        assistantMode.utils.studiableMetadata.b.z(iRequireActivity, hVar);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setRetainInstance(true);
        com.onetrust.otpublishers.headless.UI.viewmodel.d dVarS = S();
        Bundle arguments = getArguments();
        dVarS.getClass();
        if (arguments != null) {
            dVarS.g = arguments.getString("ALWAYS_ACTIVE_TEXT", "Always Active");
            dVarS.h = arguments.getString("ALWAYS_ACTIVE_TEXT_COLOR");
            dVarS.f = arguments.getString("sdkLevelOptOutShow");
            String string = arguments.getString("OT_GROUP_ID_LIST");
            if (string != null && string.length() != 0) {
                String strO = kotlin.text.D.o(kotlin.text.D.o(string, "[", "", false), "]", "", false);
                int length = strO.length() - 1;
                int i = 0;
                boolean z = false;
                while (i <= length) {
                    boolean z2 = Intrinsics.g(strO.charAt(!z ? i : length), 32) <= 0;
                    if (z) {
                        if (!z2) {
                            break;
                        } else {
                            length--;
                        }
                    } else if (z2) {
                        i++;
                    } else {
                        z = true;
                    }
                }
                dVarS.p = (String[]) StringsKt__StringsKt.split$default(strO.subSequence(i, length + 1).toString(), new String[]{","}, false, 0, 6, null).toArray(new String[0]);
                ArrayList arrayList = new ArrayList();
                for (String str : dVarS.p) {
                    int length2 = str.length() - 1;
                    int i2 = 0;
                    boolean z3 = false;
                    while (i2 <= length2) {
                        boolean z4 = Intrinsics.g(str.charAt(!z3 ? i2 : length2), 32) <= 0;
                        if (z3) {
                            if (!z4) {
                                break;
                            } else {
                                length2--;
                            }
                        } else if (z4) {
                            i2++;
                        } else {
                            z3 = true;
                        }
                    }
                    arrayList.add(str.subSequence(i2, length2 + 1).toString());
                    int length3 = str.length() - 1;
                    int i3 = 0;
                    boolean z5 = false;
                    while (i3 <= length3) {
                        boolean z6 = Intrinsics.g(str.charAt(!z5 ? i3 : length3), 32) <= 0;
                        if (z5) {
                            if (!z6) {
                                break;
                            } else {
                                length3--;
                            }
                        } else if (z6) {
                            i3++;
                        } else {
                            z5 = true;
                        }
                    }
                    dVarS.j = str.subSequence(i3, length3 + 1).toString();
                }
                dVarS.q.l(arrayList);
            }
        }
        androidx.fragment.app.I activity = getActivity();
        if (com.google.mlkit.common.internal.model.a.n(activity, OTFragmentTags.OT_SDK_LIST_FRAGMENT_TAG)) {
            SharedPreferences sharedPreferencesD = AbstractC3705q4.d(activity);
            String str2 = OTThemeConstants.NO_SDK_THEME_OVERRIDE;
            String string2 = sharedPreferencesD.getString("OT_UX_SDK_THEME", OTThemeConstants.NO_SDK_THEME_OVERRIDE);
            if (com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                string2 = OTThemeConstants.NO_SDK_THEME_OVERRIDE;
            }
            if (!string2.equals(OTThemeConstants.OT_SDK_UI_THEME)) {
                String string3 = activity.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOT_SDK_APP_CONFIGURATION", 0).getString("OT_UX_SDK_THEME", OTThemeConstants.NO_SDK_THEME_OVERRIDE);
                if (!com.onetrust.otpublishers.headless.Internal.a.j(string3)) {
                    str2 = string3;
                }
                if (!str2.equals(OTThemeConstants.OT_THEME_APP_COMPACT_LIGHT_NO_ACTION_BAR_LANDSCAPE_FULL_SCREEN)) {
                    return;
                }
            }
            OTLogger.c("OneTrust", 3, "set theme to OT defined theme ");
            M();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        Context contextRequireContext = requireContext();
        this.u.getClass();
        View viewJ = assistantMode.utils.studiableMetadata.b.j(contextRequireContext, inflater, viewGroup, R.layout.fragment_ot_sdk_list);
        View viewC = AbstractC3375o2.c(R.id.main_layout, viewJ);
        if (viewC == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewJ.getResources().getResourceName(R.id.main_layout)));
        }
        int i = R.id.back_from_sdklist;
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.back_from_sdklist, viewC);
        if (imageView != null) {
            i = R.id.filter_sdk;
            ImageView imageView2 = (ImageView) AbstractC3375o2.c(R.id.filter_sdk, viewC);
            if (imageView2 != null) {
                i = R.id.rv_sdk_list;
                RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.rv_sdk_list, viewC);
                if (recyclerView != null) {
                    i = R.id.sdk_allow_all_title;
                    TextView textView = (TextView) AbstractC3375o2.c(R.id.sdk_allow_all_title, viewC);
                    if (textView != null) {
                        i = R.id.sdk_allow_all_toggle;
                        SwitchCompat switchCompat = (SwitchCompat) AbstractC3375o2.c(R.id.sdk_allow_all_toggle, viewC);
                        if (switchCompat != null) {
                            i = R.id.sdk_list_allow_all_layout;
                            if (((LinearLayout) AbstractC3375o2.c(R.id.sdk_list_allow_all_layout, viewC)) != null) {
                                i = R.id.sdk_list_page_title;
                                TextView textView2 = (TextView) AbstractC3375o2.c(R.id.sdk_list_page_title, viewC);
                                if (textView2 != null) {
                                    RelativeLayout relativeLayout = (RelativeLayout) viewC;
                                    i = R.id.sdk_title;
                                    TextView textView3 = (TextView) AbstractC3375o2.c(R.id.sdk_title, viewC);
                                    if (textView3 != null) {
                                        i = R.id.search_sdk;
                                        SearchView searchView = (SearchView) AbstractC3375o2.c(R.id.search_sdk, viewC);
                                        if (searchView != null) {
                                            i = R.id.view2;
                                            if (AbstractC3375o2.c(R.id.view2, viewC) != null) {
                                                i = R.id.view3;
                                                if (AbstractC3375o2.c(R.id.view3, viewC) != null) {
                                                    CoordinatorLayout coordinatorLayout = (CoordinatorLayout) viewJ;
                                                    this.q = new com.onetrust.otpublishers.headless.databinding.b(coordinatorLayout, new com.onetrust.otpublishers.headless.databinding.f(relativeLayout, imageView, imageView2, recyclerView, textView, switchCompat, textView2, relativeLayout, textView3, searchView), coordinatorLayout);
                                                    Intrinsics.checkNotNullExpressionValue(coordinatorLayout, "binding.root");
                                                    return coordinatorLayout;
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
        throw new NullPointerException("Missing required view with ID: ".concat(viewC.getResources().getResourceName(i)));
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        super.onDestroyView();
        this.q = null;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle outState) {
        Intrinsics.checkNotNullParameter(outState, "outState");
        outState.putInt("NAV_FROM_PCDETAILS", !S().i ? 1 : 0);
        super.onSaveInstanceState(outState);
    }

    /*  JADX ERROR: JadxRuntimeException in pass: ModVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Can't remove SSA var: r10v8 com.onetrust.otpublishers.headless.UI.DataModels.i, still in use, count: 2, list:
          (r10v8 com.onetrust.otpublishers.headless.UI.DataModels.i) from 0x017a: MOVE (r19v0 com.onetrust.otpublishers.headless.UI.DataModels.i) = (r10v8 com.onetrust.otpublishers.headless.UI.DataModels.i)
          (r10v8 com.onetrust.otpublishers.headless.UI.DataModels.i) from 0x018e: MOVE (r19v3 com.onetrust.otpublishers.headless.UI.DataModels.i) = (r10v8 com.onetrust.otpublishers.headless.UI.DataModels.i)
        	at jadx.core.utils.InsnRemover.removeSsaVar(InsnRemover.java:162)
        	at jadx.core.utils.InsnRemover.unbindResult(InsnRemover.java:127)
        	at jadx.core.utils.InsnRemover.unbindInsn(InsnRemover.java:91)
        	at jadx.core.utils.InsnRemover.addAndUnbind(InsnRemover.java:57)
        	at jadx.core.dex.visitors.ModVisitor.removeStep(ModVisitor.java:463)
        	at jadx.core.dex.visitors.ModVisitor.visit(ModVisitor.java:97)
        */
    @Override // androidx.fragment.app.Fragment
    public final void onViewCreated(android.view.View r26, android.os.Bundle r27) {
        /*
            Method dump skipped, instructions count: 735
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.s.onViewCreated(android.view.View, android.os.Bundle):void");
    }
}
