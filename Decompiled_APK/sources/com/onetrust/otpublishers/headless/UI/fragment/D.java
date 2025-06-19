package com.onetrust.otpublishers.headless.UI.fragment;

import android.app.Application;
import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Resources;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatButton;
import androidx.appcompat.widget.SearchView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.cardview.widget.CardView;
import androidx.lifecycle.Y;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.ads.Gj;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3641i4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3657k4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3665l4;
import com.google.android.gms.measurement.internal.Z;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import com.onetrust.otpublishers.headless.UI.adapter.K;
import com.quizlet.quizletandroid.R;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes2.dex */
public final class D extends com.google.android.material.bottomsheet.i {
    public static final com.google.firebase.perf.logging.b D;
    public static final /* synthetic */ kotlin.reflect.n[] E;
    public com.onetrust.otpublishers.headless.UI.adapter.E A;
    public com.onetrust.otpublishers.headless.UI.adapter.E B;
    public K C;
    public final com.quizlet.data.repository.user.a q;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e r;
    public com.onetrust.otpublishers.headless.Internal.Event.a s;
    public OTConfiguration t;
    public final assistantMode.utils.studiableMetadata.b u;
    public com.google.android.material.bottomsheet.i v;
    public OTPublishersHeadlessSDK w;
    public m x;
    public I y;
    public ViewOnClickListenerC4064h z;

    static {
        kotlin.jvm.internal.B b = new kotlin.jvm.internal.B(D.class, "binding", "getBinding()Lcom/onetrust/otpublishers/headless/databinding/FragmentOtVendorsListBinding;", 0);
        kotlin.jvm.internal.K.a.getClass();
        E = new kotlin.reflect.n[]{b};
        D = new com.google.firebase.perf.logging.b(22);
    }

    public D() {
        B viewBindingFactory = B.a;
        Intrinsics.checkNotNullParameter(this, "<this>");
        Intrinsics.checkNotNullParameter(viewBindingFactory, "viewBindingFactory");
        this.q = new com.quizlet.data.repository.user.a(this, viewBindingFactory);
        C c = new C(this, 1);
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new assistantMode.experiments.a(new C(this, 0), 6));
        this.r = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(com.onetrust.otpublishers.headless.UI.viewmodel.e.class), new C4062f(kVarA, 4), c, new C4062f(kVarA, 5));
        this.u = new assistantMode.utils.studiableMetadata.b(22);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0053  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void T(com.onetrust.otpublishers.headless.UI.fragment.D r9, java.lang.String r10, boolean r11, java.lang.String r12) throws android.content.res.Resources.NotFoundException {
        /*
            Method dump skipped, instructions count: 287
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.D.T(com.onetrust.otpublishers.headless.UI.fragment.D, java.lang.String, boolean, java.lang.String):void");
    }

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        Intrinsics.checkNotNullExpressionValue(dialogK, "super.onCreateDialog(savedInstanceState)");
        dialogK.setOnShowListener(new com.onetrust.otpublishers.headless.UI.TVUI.fragments.e(this, 12));
        return dialogK;
    }

    public final com.onetrust.otpublishers.headless.databinding.c Q() {
        return (com.onetrust.otpublishers.headless.databinding.c) this.q.a(this, E[0]);
    }

    public final void R(OTPublishersHeadlessSDK otPublishersHeadlessSDK) {
        Intrinsics.checkNotNullParameter(otPublishersHeadlessSDK, "otPublishersHeadlessSDK");
        this.w = otPublishersHeadlessSDK;
    }

    public final void S(com.onetrust.otpublishers.headless.UI.DataModels.l lVar, AppCompatButton appCompatButton, AppCompatButton appCompatButton2, AppCompatButton appCompatButton3) {
        com.onetrust.otpublishers.headless.databinding.g gVar = Q().b;
        String str = (String) lVar.i.e;
        com.onetrust.otpublishers.headless.UI.viewmodel.e eVarX = X();
        String str2 = (String) ((com.onetrust.otpublishers.headless.UI.DataModels.l) AbstractC3665l4.a(eVarX.h)).i.f;
        String str3 = null;
        if (str2 == null || str2.length() == 0) {
            str2 = null;
        }
        if (str2 == null) {
            str2 = ((com.onetrust.otpublishers.headless.UI.DataModels.l) AbstractC3665l4.a(eVarX.h)).j;
        }
        com.onetrust.otpublishers.headless.UI.viewmodel.e eVarX2 = X();
        String str4 = (String) ((com.onetrust.otpublishers.headless.UI.DataModels.l) AbstractC3665l4.a(eVarX2.h)).k.b;
        if (str4 != null && str4.length() != 0) {
            str3 = str4;
        }
        if (str3 == null) {
            str3 = ((com.onetrust.otpublishers.headless.UI.DataModels.l) AbstractC3665l4.a(eVarX2.h)).l;
        }
        AbstractC3641i4.c(appCompatButton, str2);
        Intrinsics.checkNotNullParameter(appCompatButton, "<this>");
        if (str != null && str.length() != 0) {
            appCompatButton.setBackgroundColor(Color.parseColor(str));
        }
        AbstractC3641i4.c(appCompatButton2, str3);
        appCompatButton2.setBackgroundColor(0);
        AbstractC3641i4.c(appCompatButton3, str3);
        appCompatButton3.setBackgroundColor(0);
        ((CardView) gVar.p).setCardBackgroundColor(0);
    }

    public final void U(String str, String str2) {
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK;
        if (str2.equals(OTVendorListMode.IAB)) {
            OTPublishersHeadlessSDK oTPublishersHeadlessSDK2 = X().f;
            if ((oTPublishersHeadlessSDK2 != null ? oTPublishersHeadlessSDK2.getVendorDetails(str2, str) : null) == null && (oTPublishersHeadlessSDK = X().f) != null) {
                oTPublishersHeadlessSDK.reInitVendorArray();
            }
        }
        if (str2.equals(OTVendorListMode.IAB)) {
            I i = this.y;
            if (i == null) {
                Intrinsics.m("vendorsDetailsFragment");
                throw null;
            }
            if (i.isAdded() || getActivity() == null) {
                return;
            }
            I i2 = this.y;
            if (i2 == null) {
                Intrinsics.m("vendorsDetailsFragment");
                throw null;
            }
            OTPublishersHeadlessSDK oTPublishersHeadlessSDK3 = X().f;
            if (oTPublishersHeadlessSDK3 != null) {
                i2.Y = oTPublishersHeadlessSDK3;
            }
            i2.C1 = this.s;
            i2.setArguments(AbstractC3206m6.a(new Pair("vendorId", str)));
            i2.q1 = new w(this);
            I i3 = this.y;
            if (i3 == null) {
                Intrinsics.m("vendorsDetailsFragment");
                throw null;
            }
            com.google.mlkit.common.internal.model.a.o(i3, requireActivity(), OTFragmentTags.OT_VENDOR_DETAILS_FRAGMENT_TAG);
        }
        if (str2.equals(OTVendorListMode.GENERAL)) {
            ViewOnClickListenerC4064h viewOnClickListenerC4064h = this.z;
            if (viewOnClickListenerC4064h == null) {
                Intrinsics.m("vendorsGeneralDetailsFragment");
                throw null;
            }
            if (viewOnClickListenerC4064h.isAdded() || getActivity() == null) {
                return;
            }
            ViewOnClickListenerC4064h viewOnClickListenerC4064h2 = this.z;
            if (viewOnClickListenerC4064h2 == null) {
                Intrinsics.m("vendorsGeneralDetailsFragment");
                throw null;
            }
            OTPublishersHeadlessSDK oTPublishersHeadlessSDK4 = X().f;
            if (oTPublishersHeadlessSDK4 != null) {
                viewOnClickListenerC4064h2.y = oTPublishersHeadlessSDK4;
            }
            viewOnClickListenerC4064h2.Z = this.s;
            viewOnClickListenerC4064h2.setArguments(AbstractC3206m6.a(new Pair("vendorId", str)));
            viewOnClickListenerC4064h2.F = new w(this);
            ViewOnClickListenerC4064h viewOnClickListenerC4064h3 = this.z;
            if (viewOnClickListenerC4064h3 == null) {
                Intrinsics.m("vendorsGeneralDetailsFragment");
                throw null;
            }
            com.google.mlkit.common.internal.model.a.o(viewOnClickListenerC4064h3, requireActivity(), OTFragmentTags.OT_GENERAL_VENDOR_DETAILS_TAG);
        }
        if (str2.equals(OTVendorListMode.GOOGLE)) {
            androidx.work.impl.model.c cVarC = new androidx.browser.customtabs.k(0, false).c();
            Intrinsics.checkNotNullExpressionValue(cVarC, "builder.build()");
            OTPublishersHeadlessSDK oTPublishersHeadlessSDK5 = X().f;
            JSONObject vendorDetails = oTPublishersHeadlessSDK5 != null ? oTPublishersHeadlessSDK5.getVendorDetails(str2, str) : null;
            String strA = vendorDetails != null ? AbstractC3657k4.a("policyUrl", vendorDetails) : null;
            if (strA == null || strA.length() == 0) {
                return;
            }
            Uri uri = Uri.parse(strA);
            Context context = getContext();
            if (context != null) {
                cVarC.v(context, uri);
            }
        }
    }

    public final void V(Map map) {
        OTConfiguration oTConfiguration = this.t;
        String str = (String) AbstractC3665l4.a(X().i);
        m mVar = new m();
        Bundle bundle = new Bundle();
        bundle.putString(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_VENDOR_LIST_FILTER_FRAGMENT_TAG);
        mVar.setArguments(bundle);
        mVar.B = map;
        mVar.A = map;
        mVar.D = oTConfiguration;
        mVar.G = str;
        Intrinsics.checkNotNullExpressionValue(mVar, "newInstance(\n           …ireValue(),\n            )");
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = X().f;
        if (oTPublishersHeadlessSDK != null) {
            mVar.y = oTPublishersHeadlessSDK;
        }
        mVar.z = new w(this);
        this.x = mVar;
    }

    public final void W(boolean z, com.onetrust.otpublishers.headless.UI.DataModels.l lVar) {
        com.onetrust.otpublishers.headless.databinding.g gVar = Q().b;
        String str = z ? lVar.c : lVar.d;
        if (str == null) {
            return;
        }
        ((ImageView) gVar.j).getDrawable().setTint(Color.parseColor(str));
    }

    public final com.onetrust.otpublishers.headless.UI.viewmodel.e X() {
        return (com.onetrust.otpublishers.headless.UI.viewmodel.e) this.r.getValue();
    }

    public final void Y(com.onetrust.otpublishers.headless.UI.DataModels.l lVar) {
        com.onetrust.otpublishers.headless.databinding.g gVar = Q().b;
        com.onetrust.otpublishers.headless.UI.viewmodel.e eVarX = X();
        eVarX.getClass();
        Intrinsics.checkNotNullParameter(OTVendorListMode.GENERAL, "newMode");
        eVarX.i.l(OTVendorListMode.GENERAL);
        X().D();
        ImageView filterVendors = (ImageView) gVar.j;
        Intrinsics.checkNotNullExpressionValue(filterVendors, "filterVendors");
        filterVendors.setVisibility(0);
        SearchView searchVendor = (SearchView) gVar.o;
        Intrinsics.checkNotNullExpressionValue(searchVendor, "searchVendor");
        searchVendor.setVisibility(0);
        K k = this.C;
        if (k == null) {
            Intrinsics.m("generalVendorAdapter");
            throw null;
        }
        ((RecyclerView) gVar.n).setAdapter(k);
        boolean z = lVar.m;
        SwitchCompat allConsentToggle = (SwitchCompat) gVar.h;
        Intrinsics.checkNotNullExpressionValue(allConsentToggle, "allConsentToggle");
        allConsentToggle.setVisibility(z ? 0 : 8);
        TextView vendorAllowAllTitle = gVar.g;
        Intrinsics.checkNotNullExpressionValue(vendorAllowAllTitle, "vendorAllowAllTitle");
        vendorAllowAllTitle.setVisibility(z ? 0 : 8);
        View view3 = gVar.b;
        Intrinsics.checkNotNullExpressionValue(view3, "view3");
        view3.setVisibility(z ? 0 : 8);
        AppCompatButton buttonGeneralVendors = (AppCompatButton) gVar.k;
        Intrinsics.checkNotNullExpressionValue(buttonGeneralVendors, "buttonGeneralVendors");
        AppCompatButton buttonIabVendors = (AppCompatButton) gVar.m;
        Intrinsics.checkNotNullExpressionValue(buttonIabVendors, "buttonIabVendors");
        AppCompatButton buttonGoogleVendors = (AppCompatButton) gVar.l;
        Intrinsics.checkNotNullExpressionValue(buttonGoogleVendors, "buttonGoogleVendors");
        S(lVar, buttonGeneralVendors, buttonIabVendors, buttonGoogleVendors);
        W(!((Map) AbstractC3665l4.a(X().l)).isEmpty(), lVar);
    }

    public final void a0(com.onetrust.otpublishers.headless.UI.DataModels.l lVar) {
        com.onetrust.otpublishers.headless.databinding.g gVar = Q().b;
        com.onetrust.otpublishers.headless.UI.viewmodel.e eVarX = X();
        eVarX.getClass();
        Intrinsics.checkNotNullParameter(OTVendorListMode.GOOGLE, "newMode");
        eVarX.i.l(OTVendorListMode.GOOGLE);
        X().D();
        ImageView filterVendors = (ImageView) gVar.j;
        Intrinsics.checkNotNullExpressionValue(filterVendors, "filterVendors");
        filterVendors.setVisibility(8);
        SearchView searchVendor = (SearchView) gVar.o;
        Intrinsics.checkNotNullExpressionValue(searchVendor, "searchVendor");
        searchVendor.setVisibility(0);
        SwitchCompat allConsentToggle = (SwitchCompat) gVar.h;
        Intrinsics.checkNotNullExpressionValue(allConsentToggle, "allConsentToggle");
        allConsentToggle.setVisibility(0);
        TextView vendorAllowAllTitle = gVar.g;
        Intrinsics.checkNotNullExpressionValue(vendorAllowAllTitle, "vendorAllowAllTitle");
        vendorAllowAllTitle.setVisibility(0);
        View view3 = gVar.b;
        Intrinsics.checkNotNullExpressionValue(view3, "view3");
        view3.setVisibility(0);
        com.onetrust.otpublishers.headless.UI.adapter.E e = this.B;
        if (e == null) {
            Intrinsics.m("googleVendorAdapter");
            throw null;
        }
        ((RecyclerView) gVar.n).setAdapter(e);
        AppCompatButton buttonGoogleVendors = (AppCompatButton) gVar.l;
        Intrinsics.checkNotNullExpressionValue(buttonGoogleVendors, "buttonGoogleVendors");
        AppCompatButton buttonIabVendors = (AppCompatButton) gVar.m;
        Intrinsics.checkNotNullExpressionValue(buttonIabVendors, "buttonIabVendors");
        AppCompatButton buttonGeneralVendors = (AppCompatButton) gVar.k;
        Intrinsics.checkNotNullExpressionValue(buttonGeneralVendors, "buttonGeneralVendors");
        S(lVar, buttonGoogleVendors, buttonIabVendors, buttonGeneralVendors);
    }

    public final void b0(com.onetrust.otpublishers.headless.UI.DataModels.l lVar) {
        com.onetrust.otpublishers.headless.databinding.g gVar = Q().b;
        com.onetrust.otpublishers.headless.UI.viewmodel.e eVarX = X();
        eVarX.getClass();
        Intrinsics.checkNotNullParameter(OTVendorListMode.IAB, "newMode");
        eVarX.i.l(OTVendorListMode.IAB);
        X().D();
        ImageView filterVendors = (ImageView) gVar.j;
        Intrinsics.checkNotNullExpressionValue(filterVendors, "filterVendors");
        filterVendors.setVisibility(0);
        SearchView searchVendor = (SearchView) gVar.o;
        Intrinsics.checkNotNullExpressionValue(searchVendor, "searchVendor");
        searchVendor.setVisibility(0);
        SwitchCompat allConsentToggle = (SwitchCompat) gVar.h;
        Intrinsics.checkNotNullExpressionValue(allConsentToggle, "allConsentToggle");
        allConsentToggle.setVisibility(0);
        TextView vendorAllowAllTitle = gVar.g;
        Intrinsics.checkNotNullExpressionValue(vendorAllowAllTitle, "vendorAllowAllTitle");
        vendorAllowAllTitle.setVisibility(0);
        View view3 = gVar.b;
        Intrinsics.checkNotNullExpressionValue(view3, "view3");
        view3.setVisibility(0);
        com.onetrust.otpublishers.headless.UI.adapter.E e = this.A;
        if (e == null) {
            Intrinsics.m("iabVendorAdapter");
            throw null;
        }
        ((RecyclerView) gVar.n).setAdapter(e);
        AppCompatButton buttonIabVendors = (AppCompatButton) gVar.m;
        Intrinsics.checkNotNullExpressionValue(buttonIabVendors, "buttonIabVendors");
        AppCompatButton buttonGeneralVendors = (AppCompatButton) gVar.k;
        Intrinsics.checkNotNullExpressionValue(buttonGeneralVendors, "buttonGeneralVendors");
        AppCompatButton buttonGoogleVendors = (AppCompatButton) gVar.l;
        Intrinsics.checkNotNullExpressionValue(buttonGoogleVendors, "buttonGoogleVendors");
        S(lVar, buttonIabVendors, buttonGeneralVendors, buttonGoogleVendors);
        Intrinsics.checkNotNullExpressionValue(AbstractC3665l4.a(X().k), "_selectedFilterMap.requireValue()");
        W(!((Map) r0).isEmpty(), lVar);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        LinkedHashMap selectedMap;
        super.onCreate(bundle);
        int i = 1;
        setRetainInstance(true);
        com.onetrust.otpublishers.headless.UI.viewmodel.e eVarX = X();
        Bundle arguments = getArguments();
        eVarX.getClass();
        if (arguments != null) {
            String newMode = (arguments.containsKey("generalVendors") && arguments.getBoolean("generalVendors")) ? OTVendorListMode.GENERAL : OTVendorListMode.IAB;
            Intrinsics.checkNotNullParameter(newMode, "newMode");
            eVarX.i.l(newMode);
            String string = arguments.getString("PURPOSE_MAP");
            boolean zC = eVarX.C();
            Y y = eVarX.l;
            Y y2 = eVarX.k;
            Map map = (Map) (zC ? y2.d() : y.d());
            if (map == null || map.isEmpty()) {
                if (string == null || string.length() == 0 || string.equals("{}")) {
                    selectedMap = null;
                } else {
                    String strSubstring = string.substring(1, string.length() - 1);
                    Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
                    int i2 = 6;
                    String[] strArr = (String[]) StringsKt__StringsKt.split$default(strSubstring, new String[]{","}, false, 0, 6, null).toArray(new String[0]);
                    selectedMap = new LinkedHashMap();
                    int length = strArr.length;
                    int i3 = 0;
                    while (i3 < length) {
                        String[] strArr2 = (String[]) StringsKt__StringsKt.split$default(strArr[i3], new String[]{SimpleComparison.EQUAL_TO_OPERATION}, false, 0, i2, null).toArray(new String[0]);
                        String str = strArr2[0];
                        int length2 = str.length() - i;
                        int i4 = i;
                        int i5 = 0;
                        int i6 = 0;
                        while (i5 <= length2) {
                            int i7 = Intrinsics.g(str.charAt(i6 == 0 ? i5 : length2), 32) <= 0 ? i4 : 0;
                            if (i6 == 0) {
                                if (i7 == 0) {
                                    i6 = i4;
                                } else {
                                    i5++;
                                }
                            } else if (i7 == 0) {
                                break;
                            } else {
                                length2--;
                            }
                        }
                        String string2 = str.subSequence(i5, length2 + 1).toString();
                        String str2 = strArr2[i4];
                        int length3 = str2.length() - 1;
                        int i8 = 0;
                        int i9 = 0;
                        while (i8 <= length3) {
                            int i10 = Intrinsics.g(str2.charAt(i9 == 0 ? i8 : length3), 32) <= 0 ? i4 : 0;
                            if (i9 == 0) {
                                if (i10 == 0) {
                                    i9 = i4;
                                } else {
                                    i8++;
                                }
                            } else if (i10 == 0) {
                                break;
                            } else {
                                length3--;
                            }
                        }
                        selectedMap.put(string2, str2.subSequence(i8, length3 + 1).toString());
                        i3++;
                        i = i4;
                        i2 = 6;
                    }
                }
                if (selectedMap == null) {
                    selectedMap = new LinkedHashMap();
                }
                Intrinsics.checkNotNullParameter(selectedMap, "selectedMap");
                if (eVarX.C()) {
                    y2.l(selectedMap);
                } else {
                    y.l(selectedMap);
                }
                eVarX.D();
            }
        }
        androidx.fragment.app.I activity = getActivity();
        if (com.google.mlkit.common.internal.model.a.n(activity, OTFragmentTags.OT_VENDOR_LIST_FRAGMENT_TAG)) {
            SharedPreferences sharedPreferences = activity.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOT_SDK_APP_CONFIGURATION", 0);
            String str3 = OTThemeConstants.NO_SDK_THEME_OVERRIDE;
            String string3 = sharedPreferences.getString("OT_UX_SDK_THEME", OTThemeConstants.NO_SDK_THEME_OVERRIDE);
            if (com.onetrust.otpublishers.headless.Internal.a.j(string3)) {
                string3 = OTThemeConstants.NO_SDK_THEME_OVERRIDE;
            }
            if (!string3.equals(OTThemeConstants.OT_SDK_UI_THEME)) {
                String string4 = activity.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOT_SDK_APP_CONFIGURATION", 0).getString("OT_UX_SDK_THEME", OTThemeConstants.NO_SDK_THEME_OVERRIDE);
                if (!com.onetrust.otpublishers.headless.Internal.a.j(string4)) {
                    str3 = string4;
                }
                if (!str3.equals(OTThemeConstants.OT_THEME_APP_COMPACT_LIGHT_NO_ACTION_BAR_LANDSCAPE_FULL_SCREEN)) {
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
        View viewJ = assistantMode.utils.studiableMetadata.b.j(contextRequireContext, inflater, viewGroup, R.layout.fragment_ot_vendors_list);
        Intrinsics.checkNotNullExpressionValue(viewJ, "uiUtils.getOTView(requir…fragment_ot_vendors_list)");
        return viewJ;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        super.onDestroyView();
        OTVendorUtils oTVendorUtils = X().g;
        if (oTVendorUtils != null) {
            oTVendorUtils.setSelectAllButtonListener(null);
            Unit unit = Unit.a;
        }
        this.s = null;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) throws JSONException {
        String str;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z;
        String string;
        String string2;
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        int iD = assistantMode.utils.studiableMetadata.b.d(requireContext(), this.t);
        com.onetrust.otpublishers.headless.UI.viewmodel.e eVarX = X();
        if (this.w == null) {
            Context context = getContext();
            Intrinsics.d(context);
            this.w = new OTPublishersHeadlessSDK(context);
        }
        OTPublishersHeadlessSDK otPublishersHeadlessSDK = this.w;
        Intrinsics.d(otPublishersHeadlessSDK);
        eVarX.getClass();
        Intrinsics.checkNotNullParameter(otPublishersHeadlessSDK, "otPublishersHeadlessSDK");
        eVarX.f = otPublishersHeadlessSDK;
        eVarX.g = otPublishersHeadlessSDK.getOtVendorUtils();
        eVarX.d = iD;
        Gj vlDataConfig = new Gj();
        com.onetrust.otpublishers.headless.UI.mobiledatautils.b pcDataConfig = new com.onetrust.otpublishers.headless.UI.mobiledatautils.b();
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = eVarX.f;
        String string3 = "";
        if (oTPublishersHeadlessSDK != null) {
            Application applicationA = eVarX.A();
            int i = eVarX.d;
            try {
                vlDataConfig.q = applicationA;
                JSONObject preferenceCenterData = oTPublishersHeadlessSDK.getPreferenceCenterData();
                vlDataConfig.a = preferenceCenterData;
                if (preferenceCenterData != null) {
                    com.onetrust.otpublishers.headless.UI.UIProperty.g gVarG = new com.onetrust.otpublishers.headless.UI.UIProperty.f((Application) vlDataConfig.q).g(i);
                    vlDataConfig.b = gVarG;
                    if (gVarG != null) {
                        vlDataConfig.c = gVarG.r;
                    }
                    vlDataConfig.e();
                    androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) ((androidx.webkit.internal.p) vlDataConfig.c).b;
                    mVar.b = Gj.d((JSONObject) vlDataConfig.a, (String) mVar.b, "PcTextColor");
                    String strOptString = (String) mVar.g;
                    JSONObject jSONObject = (JSONObject) vlDataConfig.a;
                    if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString) || strOptString == null) {
                        strOptString = !com.onetrust.otpublishers.headless.Internal.a.j("PCenterVendorsListText") ? jSONObject.optString("PCenterVendorsListText") : "";
                    }
                    mVar.g = strOptString;
                    ((androidx.webkit.internal.p) vlDataConfig.c).b = mVar;
                    vlDataConfig.d = Gj.c((JSONObject) vlDataConfig.a, ((com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b).k, "PCenterVendorsListText", false);
                    vlDataConfig.e = Gj.c((JSONObject) vlDataConfig.a, ((com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b).l, "PCenterAllowAllConsentText", false);
                    com.onetrust.otpublishers.headless.UI.UIProperty.g gVar = (com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b;
                    vlDataConfig.f = Gj.a(gVar.n, gVar.a);
                    vlDataConfig.g = vlDataConfig.b(((com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b).o);
                    if (!com.onetrust.otpublishers.headless.Internal.a.j(((com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b).a)) {
                        String str2 = ((com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b).a;
                        String strOptString2 = ((JSONObject) vlDataConfig.a).optString("PcBackgroundColor");
                        if (com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
                            str2 = !com.onetrust.otpublishers.headless.Internal.a.j(strOptString2) ? strOptString2 : i == 11 ? "#2F2F2F" : "#FFFFFF";
                        }
                        vlDataConfig.h = str2;
                    }
                    vlDataConfig.n = !com.onetrust.otpublishers.headless.Internal.a.j(((com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b).i) ? ((com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b).i : ((JSONObject) vlDataConfig.a).optString("PcTextColor");
                    String str3 = ((com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b).b;
                    if (str3 == null || com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
                        str3 = "#E8E8E8";
                    }
                    vlDataConfig.o = str3;
                    vlDataConfig.p = !com.onetrust.otpublishers.headless.Internal.a.j(((com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b).q) ? ((com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b).q : ((JSONObject) vlDataConfig.a).optString("PcTextColor");
                    if (((JSONObject) vlDataConfig.a).has("PCenterBackText")) {
                        ((com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b).s.b = ((JSONObject) vlDataConfig.a).optString("PCenterBackText");
                    }
                    com.onetrust.otpublishers.headless.UI.UIProperty.g gVar2 = (com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b;
                    vlDataConfig.k = gVar2.e;
                    vlDataConfig.i = gVar2.c;
                    vlDataConfig.j = gVar2.d;
                    vlDataConfig.l = !com.onetrust.otpublishers.headless.Internal.a.j(gVar2.f) ? ((com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b).f : ((JSONObject) vlDataConfig.a).getString("PcButtonColor");
                    vlDataConfig.m = ((com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b).g;
                    vlDataConfig.r = ((JSONObject) vlDataConfig.a).optString("BConsentText");
                }
            } catch (JSONException e) {
                Z.p("Error in ui property object, error message = ", e, "VLDataConfig", 6);
            }
            if (!pcDataConfig.j(eVarX.d, eVarX.A(), oTPublishersHeadlessSDK)) {
                G();
                return;
            }
        }
        OTLogger.c("VendorsList", 3, "themeMode = " + eVarX.d);
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK2 = eVarX.f;
        JSONObject preferenceCenterData2 = oTPublishersHeadlessSDK2 != null ? oTPublishersHeadlessSDK2.getPreferenceCenterData() : null;
        Intrinsics.checkNotNullParameter(vlDataConfig, "vlDataConfig");
        com.onetrust.otpublishers.headless.Internal.Preferences.e otSharedPreferenceUtils = eVarX.c;
        Intrinsics.checkNotNullParameter(otSharedPreferenceUtils, "otSharedPreferenceUtils");
        Intrinsics.checkNotNullParameter(pcDataConfig, "pcDataConfig");
        Y y = eVarX.h;
        String str4 = (String) vlDataConfig.h;
        com.onetrust.otpublishers.headless.UI.UIProperty.g gVar3 = (com.onetrust.otpublishers.headless.UI.UIProperty.g) vlDataConfig.b;
        Intrinsics.checkNotNullExpressionValue(gVar3, "vlDataConfig.vendorListUIProperty");
        String str5 = (String) vlDataConfig.l;
        String str6 = (String) vlDataConfig.m;
        String str7 = (String) vlDataConfig.o;
        String str8 = (String) vlDataConfig.k;
        String str9 = (String) vlDataConfig.i;
        String str10 = (String) vlDataConfig.j;
        androidx.constraintlayout.motion.widget.n nVar = (androidx.constraintlayout.motion.widget.n) vlDataConfig.g;
        Intrinsics.checkNotNullExpressionValue(nVar, "vlDataConfig.confirmMyChoiceProperty");
        String strA = preferenceCenterData2 != null ? AbstractC3657k4.a("PcButtonTextColor", preferenceCenterData2) : null;
        androidx.navigation.internal.m mVar2 = (androidx.navigation.internal.m) vlDataConfig.d;
        Intrinsics.checkNotNullExpressionValue(mVar2, "vlDataConfig.vlTitleTextProperty");
        String strA2 = preferenceCenterData2 != null ? AbstractC3657k4.a("PcTextColor", preferenceCenterData2) : null;
        boolean z2 = ((com.onetrust.otpublishers.headless.Internal.Preferences.d) otSharedPreferenceUtils.b.b).b().getBoolean("OT_GENERAL_VENDORS_TOGGLE_CONFIGURED", false);
        androidx.compose.runtime.internal.j jVar = (androidx.compose.runtime.internal.j) vlDataConfig.f;
        Intrinsics.checkNotNullExpressionValue(jVar, "vlDataConfig.searchBarProperty");
        if (preferenceCenterData2 != null) {
            if (preferenceCenterData2.has("PCIABVendorsText")) {
                string2 = preferenceCenterData2.getString("PCIABVendorsText");
            } else if (preferenceCenterData2.has("PCenterVendorsListText")) {
                string2 = preferenceCenterData2.getString("PCenterVendorsListText");
            } else {
                str = "";
            }
            str = string2;
        } else {
            str = null;
        }
        Application application = (Application) vlDataConfig.q;
        SharedPreferences sharedPreferences = application.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (Z.r(Boolean.FALSE, application.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0), "OT_ENABLE_MULTI_PROFILE")) {
            z = true;
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(application, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
        } else {
            fVar = null;
            z = false;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        try {
            string = sharedPreferences.getString("OT_MOBILE_DATA", "");
        } catch (JSONException e2) {
            Z.p("error while getting mobile data json, err: ", e2, "OneTrust", 6);
        }
        JSONObject jSONObject2 = !com.onetrust.otpublishers.headless.Internal.a.j(string) ? new JSONObject(string) : new JSONObject();
        if (jSONObject2.has("preferenceCenterData")) {
            JSONObject jSONObject3 = jSONObject2.getJSONObject("preferenceCenterData");
            if (jSONObject3.has("googleVendors")) {
                JSONObject jSONObject4 = jSONObject3.getJSONObject("googleVendors");
                if (jSONObject4.has(OTVendorListMode.GENERAL)) {
                    string3 = jSONObject4.getJSONObject(OTVendorListMode.GENERAL).getString("text");
                }
            }
        }
        String str11 = string3;
        String str12 = (String) vlDataConfig.r;
        String str13 = (String) vlDataConfig.p;
        String strA3 = preferenceCenterData2 != null ? AbstractC3657k4.a("PcButtonColor", preferenceCenterData2) : null;
        androidx.webkit.internal.p pVar = (androidx.webkit.internal.p) vlDataConfig.c;
        Intrinsics.checkNotNullExpressionValue(pVar, "vlDataConfig.vlPageHeaderTitle");
        androidx.navigation.internal.m mVar3 = (androidx.navigation.internal.m) vlDataConfig.e;
        Intrinsics.checkNotNullExpressionValue(mVar3, "vlDataConfig.allowAllToggleTextProperty");
        y.l(new com.onetrust.otpublishers.headless.UI.DataModels.l(str4, gVar3, str5, str6, str7, str8, str9, str10, nVar, strA, mVar2, strA2, z2, jVar, str, str11, str12, str13, strA3, pVar, mVar3, pcDataConfig.u, (String) vlDataConfig.n));
        OTVendorUtils oTVendorUtils = eVarX.g;
        if (oTVendorUtils != null) {
            oTVendorUtils.setSelectAllButtonListener(new com.google.android.material.search.a(eVarX, 16));
        }
        eVarX.D();
        eVarX.k.f(getViewLifecycleOwner(), new z(0, eVarX, this));
        final int i2 = 1;
        eVarX.l.f(getViewLifecycleOwner(), new z(i2, eVarX, this));
        final int i3 = 0;
        y.f(getViewLifecycleOwner(), new androidx.lifecycle.Z(this) { // from class: com.onetrust.otpublishers.headless.UI.fragment.A
            public final /* synthetic */ D b;

            {
                this.b = this;
            }

            /* JADX WARN: Removed duplicated region for block: B:32:0x00e7  */
            /* JADX WARN: Removed duplicated region for block: B:35:0x0129  */
            @Override // androidx.lifecycle.Z
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public final void a(java.lang.Object r25) throws org.json.JSONException, android.content.res.Resources.NotFoundException, java.lang.NumberFormatException {
                /*
                    Method dump skipped, instructions count: 1796
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.A.a(java.lang.Object):void");
            }
        });
        eVarX.m.f(getViewLifecycleOwner(), new androidx.lifecycle.Z(this) { // from class: com.onetrust.otpublishers.headless.UI.fragment.A
            public final /* synthetic */ D b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.Z
            public final void a(Object v) throws JSONException, Resources.NotFoundException, NumberFormatException {
                /*
                    Method dump skipped, instructions count: 1796
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.A.a(java.lang.Object):void");
            }
        });
        final int i4 = 2;
        eVarX.n.f(getViewLifecycleOwner(), new androidx.lifecycle.Z(this) { // from class: com.onetrust.otpublishers.headless.UI.fragment.A
            public final /* synthetic */ D b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.Z
            public final void a(Object v) throws JSONException, Resources.NotFoundException, NumberFormatException {
                /*
                    Method dump skipped, instructions count: 1796
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.A.a(java.lang.Object):void");
            }
        });
        final int i5 = 3;
        eVarX.o.f(getViewLifecycleOwner(), new androidx.lifecycle.Z(this) { // from class: com.onetrust.otpublishers.headless.UI.fragment.A
            public final /* synthetic */ D b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.Z
            public final void a(Object v) throws JSONException, Resources.NotFoundException, NumberFormatException {
                /*
                    Method dump skipped, instructions count: 1796
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.A.a(java.lang.Object):void");
            }
        });
        final int i6 = 4;
        eVarX.j.f(getViewLifecycleOwner(), new androidx.lifecycle.Z(this) { // from class: com.onetrust.otpublishers.headless.UI.fragment.A
            public final /* synthetic */ D b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.Z
            public final void a(Object v) throws JSONException, Resources.NotFoundException, NumberFormatException {
                /*
                    Method dump skipped, instructions count: 1796
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.fragment.A.a(java.lang.Object):void");
            }
        });
        com.google.mlkit.common.internal.model.a.f(getContext(), view, "VendorsList");
        OTConfiguration oTConfiguration = this.t;
        I i7 = new I();
        Bundle bundle2 = new Bundle();
        bundle2.putString("string", OTFragmentTags.OT_VENDOR_DETAILS_FRAGMENT_TAG);
        i7.setArguments(bundle2);
        i7.z1 = oTConfiguration;
        Intrinsics.checkNotNullExpressionValue(i7, "newInstance(\n           …otConfiguration\n        )");
        this.y = i7;
        OTConfiguration oTConfiguration2 = this.t;
        ViewOnClickListenerC4064h viewOnClickListenerC4064h = new ViewOnClickListenerC4064h();
        Bundle bundle3 = new Bundle();
        bundle3.putString("string", OTFragmentTags.OT_GENERAL_VENDOR_DETAILS_TAG);
        viewOnClickListenerC4064h.setArguments(bundle3);
        viewOnClickListenerC4064h.M = oTConfiguration2;
        Intrinsics.checkNotNullExpressionValue(viewOnClickListenerC4064h, "newInstance(\n           …otConfiguration\n        )");
        this.z = viewOnClickListenerC4064h;
        new Handler(Looper.getMainLooper()).post(new com.google.firebase.crashlytics.internal.metadata.q(this, 6));
    }
}
