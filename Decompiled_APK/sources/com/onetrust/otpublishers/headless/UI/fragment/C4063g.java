package com.onetrust.otpublishers.headless.UI.fragment;

import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Color;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3641i4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3689o4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3705q4;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTBannerHeightRatio;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReason;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.quizletandroid.R;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import org.json.JSONException;

@Metadata
/* renamed from: com.onetrust.otpublishers.headless.UI.fragment.g, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4063g extends com.google.android.material.bottomsheet.i implements com.onetrust.otpublishers.headless.UI.a {
    public static final com.google.firebase.heartbeatinfo.e A;
    public static final /* synthetic */ kotlin.reflect.n[] B;
    public OTPublishersHeadlessSDK q;
    public final com.quizlet.data.repository.user.a r;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e s;
    public com.onetrust.otpublishers.headless.Internal.Event.a t;
    public OTConfiguration u;
    public D v;
    public l w;
    public final assistantMode.utils.studiableMetadata.b x;
    public BottomSheetBehavior y;
    public com.google.android.material.bottomsheet.h z;

    static {
        kotlin.jvm.internal.B b = new kotlin.jvm.internal.B(C4063g.class, "binding", "getBinding()Lcom/onetrust/otpublishers/headless/databinding/FragmentOtBannerBinding;", 0);
        K.a.getClass();
        B = new kotlin.reflect.n[]{b};
        A = new com.google.firebase.heartbeatinfo.e(22);
    }

    public C4063g() {
        C4060d viewBindingFactory = C4060d.a;
        Intrinsics.checkNotNullParameter(this, "<this>");
        Intrinsics.checkNotNullParameter(viewBindingFactory, "viewBindingFactory");
        this.r = new com.quizlet.data.repository.user.a(this, viewBindingFactory);
        C4061e c4061e = new C4061e(this, 1);
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new assistantMode.experiments.a(new C4061e(this, 0), 4));
        this.s = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.onetrust.otpublishers.headless.UI.viewmodel.b.class), new C4062f(kVarA, 0), c4061e, new C4062f(kVarA, 1));
        this.x = new assistantMode.utils.studiableMetadata.b(22);
    }

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        Intrinsics.checkNotNullExpressionValue(dialogK, "super.onCreateDialog(savedInstanceState)");
        dialogK.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 2));
        return dialogK;
    }

    public final com.onetrust.otpublishers.headless.databinding.a Q() {
        return (com.onetrust.otpublishers.headless.databinding.a) this.r.a(this, B[0]);
    }

    public final void R(com.onetrust.otpublishers.headless.UI.DataModels.a aVar, com.airbnb.lottie.animation.keyframe.q qVar, androidx.room.s sVar) {
        Integer numValueOf;
        KeyEvent.Callback callback;
        String str;
        String str2;
        String str3;
        String str4;
        androidx.constraintlayout.motion.widget.n nVar;
        androidx.constraintlayout.motion.widget.n nVar2;
        androidx.constraintlayout.motion.widget.n nVar3;
        androidx.constraintlayout.motion.widget.n nVar4;
        androidx.constraintlayout.motion.widget.n nVar5;
        androidx.constraintlayout.motion.widget.n nVar6;
        String str5;
        com.onetrust.otpublishers.headless.databinding.a aVarQ = Q();
        int i = ((androidx.constraintlayout.motion.widget.n) qVar.k).c;
        int i2 = ((androidx.constraintlayout.motion.widget.n) qVar.l).c;
        int i3 = ((androidx.constraintlayout.motion.widget.n) qVar.m).c;
        LinearLayout linearLayout = Q().n;
        if (i != 0 || i2 != 0 || i3 != 0) {
            try {
                OTLogger.c("OTSDKBanner", 3, "Reordering buttons as per admin configuration");
                linearLayout.removeAllViews();
                HashMap map = new HashMap();
                TextView textView = Q().v;
                Intrinsics.checkNotNullExpressionValue(textView, "binding.showVendorsList");
                map.put(0, textView);
                Integer numValueOf2 = Integer.valueOf(i);
                Button button = Q().l;
                Intrinsics.checkNotNullExpressionValue(button, "binding.btnAcceptCookies");
                map.put(numValueOf2, button);
                Integer numValueOf3 = Integer.valueOf(i2);
                Button button2 = Q().m;
                Intrinsics.checkNotNullExpressionValue(button2, "binding.btnRejectCookies");
                map.put(numValueOf3, button2);
                if (Boolean.parseBoolean((String) ((androidx.constraintlayout.motion.widget.n) qVar.m).o)) {
                    numValueOf = Integer.valueOf(i3);
                    callback = Q().s;
                    Intrinsics.checkNotNullExpressionValue(callback, "binding.cookiesSetting");
                } else {
                    numValueOf = Integer.valueOf(i3);
                    callback = Q().t;
                    Intrinsics.checkNotNullExpressionValue(callback, "binding.cookiesSettingButton");
                }
                map.put(numValueOf, callback);
                Set setKeySet = map.keySet();
                Intrinsics.checkNotNullExpressionValue(setKeySet, "buttonMap.keys");
                CollectionsKt.n0(setKeySet, new com.google.zxing.aztec.encoder.c(4));
                Iterator it2 = map.keySet().iterator();
                while (it2.hasNext()) {
                    linearLayout.addView((View) map.get((Integer) it2.next()));
                }
            } catch (Exception e) {
                OTLogger.c("OTSDKBanner", 6, "Reordering buttons failed, falling back to default: " + e);
                LinearLayout linearLayout2 = Q().n;
                linearLayout2.removeAllViews();
                linearLayout2.addView(Q().v);
                linearLayout2.addView(Q().l);
                linearLayout2.addView(Q().m);
                linearLayout2.addView(Q().t);
                linearLayout2.addView(Q().s);
            }
        }
        Button button3 = aVarQ.l;
        androidx.constraintlayout.motion.widget.n nVar7 = (androidx.constraintlayout.motion.widget.n) qVar.k;
        Intrinsics.checkNotNullExpressionValue(nVar7, "otBannerUIProperty.acceptAllButtonProperty");
        button3.setText(aVar.b);
        Intrinsics.checkNotNullExpressionValue(button3, "");
        button3.setVisibility((!aVar.m || (str5 = aVar.b) == null || str5.length() == 0) ? 8 : 0);
        com.onetrust.otpublishers.headless.UI.viewmodel.b bVarT = T();
        com.onetrust.otpublishers.headless.UI.DataModels.a aVar2 = (com.onetrust.otpublishers.headless.UI.DataModels.a) bVarT.e.d();
        String str6 = (aVar2 == null || (nVar6 = (androidx.constraintlayout.motion.widget.n) aVar2.t.k) == null) ? null : (String) nVar6.e;
        if (str6 == null || str6.length() == 0) {
            str6 = null;
        }
        if (str6 != null) {
            str = str6;
        } else {
            com.onetrust.otpublishers.headless.UI.DataModels.a aVar3 = (com.onetrust.otpublishers.headless.UI.DataModels.a) bVarT.e.d();
            if (aVar3 != null) {
                str6 = aVar3.i;
                str = str6;
            } else {
                str = null;
            }
        }
        com.onetrust.otpublishers.headless.UI.viewmodel.b bVarT2 = T();
        com.onetrust.otpublishers.headless.UI.DataModels.a aVar4 = (com.onetrust.otpublishers.headless.UI.DataModels.a) bVarT2.e.d();
        String str7 = (aVar4 == null || (nVar5 = (androidx.constraintlayout.motion.widget.n) aVar4.t.k) == null) ? null : (String) nVar5.f;
        if (str7 == null || str7.length() == 0) {
            str7 = null;
        }
        if (str7 != null) {
            str2 = str7;
        } else {
            com.onetrust.otpublishers.headless.UI.DataModels.a aVar5 = (com.onetrust.otpublishers.headless.UI.DataModels.a) bVarT2.e.d();
            if (aVar5 != null) {
                str7 = aVar5.j;
                str2 = str7;
            } else {
                str2 = null;
            }
        }
        AbstractC3641i4.a(button3, nVar7, str, str2, (String) nVar7.g, this.u);
        androidx.constraintlayout.motion.widget.n nVar8 = (androidx.constraintlayout.motion.widget.n) qVar.l;
        Intrinsics.checkNotNullExpressionValue(nVar8, "otBannerUIProperty.rejectAllButtonProperty");
        Button button4 = aVarQ.m;
        Intrinsics.checkNotNullExpressionValue(button4, "");
        button4.setVisibility(aVar.c ? 0 : 8);
        button4.setText(aVar.d);
        com.onetrust.otpublishers.headless.UI.viewmodel.b bVarT3 = T();
        com.onetrust.otpublishers.headless.UI.DataModels.a aVar6 = (com.onetrust.otpublishers.headless.UI.DataModels.a) bVarT3.e.d();
        String str8 = (aVar6 == null || (nVar4 = (androidx.constraintlayout.motion.widget.n) aVar6.t.l) == null) ? null : (String) nVar4.e;
        if (str8 == null || str8.length() == 0) {
            str8 = null;
        }
        if (str8 != null) {
            str3 = str8;
        } else {
            com.onetrust.otpublishers.headless.UI.DataModels.a aVar7 = (com.onetrust.otpublishers.headless.UI.DataModels.a) bVarT3.e.d();
            if (aVar7 != null) {
                str8 = aVar7.i;
                str3 = str8;
            } else {
                str3 = null;
            }
        }
        com.onetrust.otpublishers.headless.UI.viewmodel.b bVarT4 = T();
        com.onetrust.otpublishers.headless.UI.DataModels.a aVar8 = (com.onetrust.otpublishers.headless.UI.DataModels.a) bVarT4.e.d();
        String str9 = (aVar8 == null || (nVar3 = (androidx.constraintlayout.motion.widget.n) aVar8.t.l) == null) ? null : (String) nVar3.f;
        if (str9 == null || str9.length() == 0) {
            str9 = null;
        }
        if (str9 != null) {
            str4 = str9;
        } else {
            com.onetrust.otpublishers.headless.UI.DataModels.a aVar9 = (com.onetrust.otpublishers.headless.UI.DataModels.a) bVarT4.e.d();
            if (aVar9 != null) {
                str9 = aVar9.j;
                str4 = str9;
            } else {
                str4 = null;
            }
        }
        AbstractC3641i4.a(button4, nVar8, str3, str4, (String) nVar8.g, this.u);
        com.onetrust.otpublishers.headless.databinding.a aVarQ2 = Q();
        androidx.constraintlayout.motion.widget.n buttonProperty = (androidx.constraintlayout.motion.widget.n) qVar.m;
        Intrinsics.checkNotNullExpressionValue(buttonProperty, "otBannerUIProperty.showPreferencesButtonProperty");
        Button button5 = aVarQ2.t;
        String str10 = aVar.a;
        button5.setText(str10);
        Intrinsics.checkNotNullExpressionValue(button5, "");
        boolean z = aVar.n;
        boolean z2 = aVar.e;
        button5.setVisibility((!z || z2) ? 8 : 0);
        com.onetrust.otpublishers.headless.UI.viewmodel.b bVarT5 = T();
        com.onetrust.otpublishers.headless.UI.DataModels.a aVar10 = (com.onetrust.otpublishers.headless.UI.DataModels.a) bVarT5.e.d();
        String str11 = (aVar10 == null || (nVar2 = (androidx.constraintlayout.motion.widget.n) aVar10.t.m) == null) ? null : (String) nVar2.e;
        if (str11 == null || str11.length() == 0) {
            str11 = null;
        }
        if (str11 == null) {
            com.onetrust.otpublishers.headless.UI.DataModels.a aVar11 = (com.onetrust.otpublishers.headless.UI.DataModels.a) bVarT5.e.d();
            str11 = aVar11 != null ? aVar11.f : null;
        }
        String strC = T().C();
        com.onetrust.otpublishers.headless.UI.viewmodel.b bVarT6 = T();
        com.onetrust.otpublishers.headless.UI.DataModels.a aVar12 = (com.onetrust.otpublishers.headless.UI.DataModels.a) bVarT6.e.d();
        String str12 = (aVar12 == null || (nVar = (androidx.constraintlayout.motion.widget.n) aVar12.t.m) == null) ? null : (String) nVar.g;
        if (str12 == null || str12.length() == 0) {
            str12 = null;
        }
        if (str12 == null) {
            com.onetrust.otpublishers.headless.UI.DataModels.a aVar13 = (com.onetrust.otpublishers.headless.UI.DataModels.a) bVarT6.e.d();
            str12 = aVar13 != null ? aVar13.g : null;
        }
        AbstractC3641i4.a(button5, buttonProperty, str11, strC, str12, this.u);
        TextView textView2 = aVarQ2.s;
        textView2.setText(str10);
        Intrinsics.checkNotNullExpressionValue(textView2, "");
        textView2.setVisibility((z && z2) ? 0 : 8);
        String strC2 = T().C();
        OTConfiguration oTConfiguration = this.u;
        Intrinsics.checkNotNullParameter(textView2, "<this>");
        Intrinsics.checkNotNullParameter(buttonProperty, "buttonProperty");
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) buttonProperty.d;
        Intrinsics.checkNotNullExpressionValue(kVar, "buttonProperty.fontProperty");
        AbstractC3689o4.c(textView2, kVar, oTConfiguration);
        String str13 = (String) kVar.d;
        if (str13 != null && str13.length() != 0) {
            String str14 = (String) kVar.d;
            Intrinsics.d(str14);
            textView2.setTextSize(Float.parseFloat(str14));
        }
        if (strC2 != null && strC2.length() != 0) {
            textView2.setTextColor(Color.parseColor(strC2));
        }
        Intrinsics.checkNotNullParameter(textView2, "<this>");
        if (sVar == null || sVar.c) {
            textView2.setPaintFlags(textView2.getPaintFlags() | 8);
        }
    }

    public final void S(String type, boolean z) throws JSONException {
        if (z) {
            com.onetrust.otpublishers.headless.UI.viewmodel.b bVarT = T();
            bVarT.getClass();
            Intrinsics.checkNotNullParameter(type, "type");
            bVarT.c.saveConsent(type);
        }
        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(2, 4);
        com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.t;
        this.x.getClass();
        assistantMode.utils.studiableMetadata.b.y(mVar, aVar);
        androidx.compose.foundation.lazy.grid.m mVar2 = new androidx.compose.foundation.lazy.grid.m(17, 4);
        mVar2.d = type;
        assistantMode.utils.studiableMetadata.b.y(mVar2, this.t);
        G();
    }

    public final com.onetrust.otpublishers.headless.UI.viewmodel.b T() {
        return (com.onetrust.otpublishers.headless.UI.viewmodel.b) this.s.getValue();
    }

    public final void U(int i) {
        com.airbnb.lottie.animation.keyframe.q qVar;
        com.google.android.material.bottomsheet.h hVar = this.z;
        String str = null;
        FrameLayout frameLayout = hVar != null ? (FrameLayout) hVar.findViewById(R.id.design_bottom_sheet) : null;
        if (frameLayout != null) {
            this.y = BottomSheetBehavior.C(frameLayout);
            ViewGroup.LayoutParams layoutParams = frameLayout.getLayoutParams();
            Intrinsics.checkNotNullExpressionValue(layoutParams, "it.layoutParams");
            int i2 = assistantMode.utils.studiableMetadata.b.i(getContext(), true);
            layoutParams.height = i2;
            com.onetrust.otpublishers.headless.UI.DataModels.a aVar = (com.onetrust.otpublishers.headless.UI.DataModels.a) T().e.d();
            if (aVar != null && (qVar = aVar.t) != null) {
                str = (String) qVar.d;
            }
            double d = 1.0d;
            if (str != null && str.length() != 0) {
                int iHashCode = str.hashCode();
                if (iHashCode != 288473524) {
                    if (iHashCode != 1945285198) {
                        if (iHashCode == 2002049644 && str.equals(OTBannerHeightRatio.ONE_HALF)) {
                            d = 0.5d;
                        }
                    } else if (str.equals(OTBannerHeightRatio.ONE_THIRD)) {
                        d = 0.33d;
                    }
                } else if (str.equals(OTBannerHeightRatio.TWO_THIRD)) {
                    d = 0.66d;
                }
            }
            if (2 != i) {
                layoutParams.height = (int) (i2 * d);
            }
            frameLayout.setLayoutParams(layoutParams);
            BottomSheetBehavior bottomSheetBehavior = this.y;
            if (bottomSheetBehavior != null) {
                bottomSheetBehavior.I(i2);
            }
        }
    }

    public final void V() {
        l lVar = this.w;
        if (lVar == null) {
            Intrinsics.m("preferenceCenterFragment");
            throw null;
        }
        if (lVar.isAdded() || getActivity() == null) {
            return;
        }
        l lVar2 = this.w;
        if (lVar2 == null) {
            Intrinsics.m("preferenceCenterFragment");
            throw null;
        }
        com.google.mlkit.common.internal.model.a.o(lVar2, requireActivity(), OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG);
        OTUIDisplayReason oTUIDisplayReason = new OTUIDisplayReason(OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SHOW_PC_CALLED, OTUIDisplayReason.getResponseMessage(OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SHOW_PC_CALLED));
        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(5, 4);
        mVar.f = oTUIDisplayReason;
        com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.t;
        this.x.getClass();
        assistantMode.utils.studiableMetadata.b.y(mVar, aVar);
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration newConfig) {
        Intrinsics.checkNotNullParameter(newConfig, "newConfig");
        super.onConfigurationChanged(newConfig);
        OTLogger.c("OTSDKBanner", 3, "onConfigurationChanged:");
        if (this.z == null && getActivity() != null) {
            OTLogger.c("OTSDKBanner", 3, "onConfigurationChanged: null instance found, recreating bottomSheetDialog");
            SharedPreferences sharedPreferencesD = AbstractC3705q4.d(requireActivity());
            String str = OTThemeConstants.NO_SDK_THEME_OVERRIDE;
            String string = sharedPreferencesD.getString("OT_UX_SDK_THEME", OTThemeConstants.NO_SDK_THEME_OVERRIDE);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                str = string;
            }
            this.z = str.equals(OTThemeConstants.OT_SDK_UI_THEME) ? new com.google.android.material.bottomsheet.h(requireActivity(), R.style.OTSDKTheme) : new com.google.android.material.bottomsheet.h(requireActivity());
        }
        U(newConfig.orientation);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setRetainInstance(true);
        Context context = getContext();
        if (com.google.mlkit.common.internal.model.a.n(context, OTFragmentTags.OT_BANNER_FRAGMENT_TAG)) {
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOT_SDK_APP_CONFIGURATION", 0);
            String str = OTThemeConstants.NO_SDK_THEME_OVERRIDE;
            String string = sharedPreferences.getString("OT_UX_SDK_THEME", OTThemeConstants.NO_SDK_THEME_OVERRIDE);
            if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                string = OTThemeConstants.NO_SDK_THEME_OVERRIDE;
            }
            if (!string.equals(OTThemeConstants.OT_SDK_UI_THEME)) {
                String string2 = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOT_SDK_APP_CONFIGURATION", 0).getString("OT_UX_SDK_THEME", OTThemeConstants.NO_SDK_THEME_OVERRIDE);
                if (!com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                    str = string2;
                }
                if (!str.equals(OTThemeConstants.OT_THEME_APP_COMPACT_LIGHT_NO_ACTION_BAR_LANDSCAPE_FULL_SCREEN)) {
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
        this.x.getClass();
        View viewJ = assistantMode.utils.studiableMetadata.b.j(contextRequireContext, inflater, viewGroup, R.layout.fragment_ot_banner);
        Intrinsics.checkNotNullExpressionValue(viewJ, "uiUtils.getOTView(requir…ayout.fragment_ot_banner)");
        return viewJ;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        super.onDestroyView();
        this.t = null;
    }

    /* JADX WARN: Removed duplicated region for block: B:155:0x041c  */
    /* JADX WARN: Removed duplicated region for block: B:160:0x0433  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x0453  */
    @Override // androidx.fragment.app.Fragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onViewCreated(android.view.View r34, android.os.Bundle r35) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 1382
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.C4063g.onViewCreated(android.view.View, android.os.Bundle):void");
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final void p(int i) {
        if (i == 1) {
            G();
            return;
        }
        if (i != 2) {
            if (i != 3) {
                return;
            }
            com.google.firebase.perf.logging.b bVar = D.D;
            com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.t;
            OTConfiguration oTConfiguration = this.u;
            bVar.getClass();
            D dA = com.google.firebase.perf.logging.b.a(aVar, oTConfiguration);
            dA.R(T().c);
            dA.v = this;
            this.v = dA;
            return;
        }
        com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = this.t;
        OTConfiguration oTConfiguration2 = this.u;
        l lVar = new l();
        Bundle bundle = new Bundle();
        bundle.putString(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG);
        lVar.setArguments(bundle);
        lVar.c1 = aVar2;
        lVar.d1 = oTConfiguration2;
        Intrinsics.checkNotNullExpressionValue(lVar, "newInstance(\n           …nfiguration\n            )");
        lVar.Z = this;
        lVar.W = T().c;
        this.w = lVar;
    }
}
