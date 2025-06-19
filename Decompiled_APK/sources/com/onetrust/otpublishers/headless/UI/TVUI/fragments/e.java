package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

import android.content.Context;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.util.DisplayMetrics;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.fragment.app.I;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.UI.fragment.C4063g;
import com.onetrust.otpublishers.headless.UI.fragment.D;
import com.onetrust.otpublishers.headless.UI.fragment.DialogInterfaceOnKeyListenerC4057a;
import com.onetrust.otpublishers.headless.UI.fragment.ViewOnClickListenerC4058b;
import com.onetrust.otpublishers.headless.UI.fragment.ViewOnClickListenerC4064h;
import com.onetrust.otpublishers.headless.UI.fragment.ViewOnClickListenerC4065i;
import com.onetrust.otpublishers.headless.UI.fragment.t;
import com.onetrust.otpublishers.headless.UI.fragment.u;
import com.onetrust.otpublishers.headless.UI.fragment.v;
import com.quizlet.baseui.base.BaseComposeBottomSheetFragment;
import com.quizlet.quizletandroid.R;
import java.lang.reflect.InvocationTargetException;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final /* synthetic */ class e implements DialogInterface.OnShowListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.google.android.material.bottomsheet.i b;

    public /* synthetic */ e(com.google.android.material.bottomsheet.i iVar, int i) {
        this.a = i;
        this.b = iVar;
    }

    @Override // android.content.DialogInterface.OnShowListener
    public final void onShow(DialogInterface dialogInterface) throws IllegalAccessException, NoSuchMethodException, Resources.NotFoundException, SecurityException, IllegalArgumentException, InvocationTargetException {
        JSONObject jSONObject;
        JSONObject jSONObject2;
        com.google.android.material.bottomsheet.h hVar;
        androidx.webkit.internal.p pVar;
        androidx.navigation.internal.m mVar;
        JSONObject jSONObject3;
        int i = 1;
        int i2 = 3;
        int i3 = 6;
        com.google.android.material.bottomsheet.i iVar = this.b;
        int i4 = 0;
        switch (this.a) {
            case 0:
                g gVar = (g) iVar;
                gVar.getClass();
                com.google.android.material.bottomsheet.h hVar2 = (com.google.android.material.bottomsheet.h) dialogInterface;
                gVar.s = hVar2;
                if (gVar.getActivity() != null && hVar2 == null) {
                    OTLogger.c("OTTV", 3, "setupFullHeight: null instance found, recreating bottomSheetDialog");
                    hVar2 = new com.google.android.material.bottomsheet.h(gVar.getActivity());
                }
                FrameLayout frameLayout = (FrameLayout) hVar2.findViewById(R.id.design_bottom_sheet);
                gVar.r = frameLayout;
                if (frameLayout != null) {
                    gVar.q = BottomSheetBehavior.C(frameLayout);
                    ViewGroup.LayoutParams layoutParams = gVar.r.getLayoutParams();
                    DisplayMetrics displayMetrics = new DisplayMetrics();
                    if (gVar.getActivity() != null) {
                        gVar.getActivity().getWindowManager().getDefaultDisplay().getMetrics(displayMetrics);
                    } else {
                        OTLogger.c("OneTrust", 6, "TV: getActivity() returned null");
                    }
                    int i5 = displayMetrics.heightPixels;
                    if (layoutParams != null) {
                        layoutParams.height = i5;
                    }
                    gVar.r.setLayoutParams(layoutParams);
                    gVar.q.J(3);
                }
                FrameLayout frameLayout2 = (FrameLayout) gVar.s.findViewById(R.id.design_bottom_sheet);
                gVar.r = frameLayout2;
                if (frameLayout2 != null) {
                    gVar.q = BottomSheetBehavior.C(frameLayout2);
                }
                gVar.s.setCancelable(false);
                gVar.s.setCanceledOnTouchOutside(false);
                BottomSheetBehavior bottomSheetBehavior = gVar.q;
                bottomSheetBehavior.J = true;
                bottomSheetBehavior.H(false);
                BottomSheetBehavior bottomSheetBehavior2 = gVar.q;
                DisplayMetrics displayMetrics2 = new DisplayMetrics();
                if (gVar.getActivity() != null) {
                    gVar.getActivity().getWindowManager().getDefaultDisplay().getMetrics(displayMetrics2);
                } else {
                    OTLogger.c("OneTrust", 6, "TV: getActivity() returned null");
                }
                bottomSheetBehavior2.I(displayMetrics2.heightPixels);
                gVar.s.setOnKeyListener(new f(gVar, i4));
                break;
            case 1:
                ViewOnClickListenerC4058b viewOnClickListenerC4058b = (ViewOnClickListenerC4058b) iVar;
                viewOnClickListenerC4058b.getClass();
                viewOnClickListenerC4058b.w = (com.google.android.material.bottomsheet.h) dialogInterface;
                assistantMode.utils.studiableMetadata.b bVar = viewOnClickListenerC4058b.z;
                I activity = viewOnClickListenerC4058b.getActivity();
                com.google.android.material.bottomsheet.h hVar3 = viewOnClickListenerC4058b.w;
                bVar.getClass();
                assistantMode.utils.studiableMetadata.b.z(activity, hVar3);
                viewOnClickListenerC4058b.w.setCancelable(false);
                viewOnClickListenerC4058b.w.setOnKeyListener(new DialogInterfaceOnKeyListenerC4057a());
                break;
            case 2:
                com.google.firebase.heartbeatinfo.e eVar = C4063g.A;
                C4063g this$0 = (C4063g) iVar;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                Intrinsics.checkNotNullParameter(dialogInterface, "dialogInterface");
                this$0.z = (com.google.android.material.bottomsheet.h) dialogInterface;
                if (com.google.mlkit.common.internal.model.a.n(this$0.getContext(), "OT_BANNERonCreateDialog")) {
                    this$0.U(this$0.getResources().getConfiguration().orientation);
                }
                com.google.android.material.bottomsheet.h hVar4 = this$0.z;
                if (hVar4 != null) {
                }
                com.google.android.material.bottomsheet.h hVar5 = this$0.z;
                if (hVar5 != null) {
                    hVar5.setCancelable(false);
                }
                com.google.android.material.bottomsheet.h hVar6 = this$0.z;
                if (hVar6 != null) {
                    hVar6.setOnKeyListener(new f(this$0, i));
                    break;
                }
                break;
            case 3:
                ViewOnClickListenerC4064h viewOnClickListenerC4064h = (ViewOnClickListenerC4064h) iVar;
                viewOnClickListenerC4064h.getClass();
                viewOnClickListenerC4064h.v = (com.google.android.material.bottomsheet.h) dialogInterface;
                assistantMode.utils.studiableMetadata.b bVar2 = viewOnClickListenerC4064h.W;
                I activity2 = viewOnClickListenerC4064h.getActivity();
                com.google.android.material.bottomsheet.h hVar7 = viewOnClickListenerC4064h.v;
                bVar2.getClass();
                assistantMode.utils.studiableMetadata.b.z(activity2, hVar7);
                viewOnClickListenerC4064h.v.setCancelable(false);
                com.google.android.material.bottomsheet.h hVar8 = viewOnClickListenerC4064h.v;
                if (hVar8 != null && (jSONObject = viewOnClickListenerC4064h.z) != null) {
                    hVar8.setTitle(jSONObject.optString("Name"));
                }
                viewOnClickListenerC4064h.v.setOnKeyListener(new f(viewOnClickListenerC4064h, 2));
                break;
            case 4:
                ViewOnClickListenerC4065i viewOnClickListenerC4065i = (ViewOnClickListenerC4065i) iVar;
                viewOnClickListenerC4065i.getClass();
                viewOnClickListenerC4065i.t = (com.google.android.material.bottomsheet.h) dialogInterface;
                assistantMode.utils.studiableMetadata.b bVar3 = viewOnClickListenerC4065i.C;
                I activity3 = viewOnClickListenerC4065i.getActivity();
                com.google.android.material.bottomsheet.h hVar9 = viewOnClickListenerC4065i.t;
                bVar3.getClass();
                assistantMode.utils.studiableMetadata.b.z(activity3, hVar9);
                viewOnClickListenerC4065i.t.setCancelable(false);
                com.google.android.material.bottomsheet.h hVar10 = viewOnClickListenerC4065i.t;
                if (hVar10 != null) {
                    hVar10.setTitle(viewOnClickListenerC4065i.E.N);
                    viewOnClickListenerC4065i.t.setOnKeyListener(new f(viewOnClickListenerC4065i, i2));
                    break;
                }
                break;
            case 5:
                com.onetrust.otpublishers.headless.UI.fragment.k kVar = (com.onetrust.otpublishers.headless.UI.fragment.k) iVar;
                kVar.getClass();
                kVar.Z = (com.google.android.material.bottomsheet.h) dialogInterface;
                assistantMode.utils.studiableMetadata.b bVar4 = kVar.F1;
                I activity4 = kVar.getActivity();
                com.google.android.material.bottomsheet.h hVar11 = kVar.Z;
                bVar4.getClass();
                assistantMode.utils.studiableMetadata.b.z(activity4, hVar11);
                kVar.Z.setCancelable(false);
                com.google.android.material.bottomsheet.h hVar12 = kVar.Z;
                if (hVar12 != null && (jSONObject2 = kVar.C1) != null) {
                    kVar.F1.getClass();
                    String strOptString = jSONObject2.optString("GroupNameMobile");
                    if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString)) {
                        strOptString = jSONObject2.optString("GroupName");
                    }
                    hVar12.setTitle(strOptString);
                }
                kVar.Z.setOnKeyListener(new f(kVar, 4));
                break;
            case 6:
                com.onetrust.otpublishers.headless.UI.fragment.l lVar = (com.onetrust.otpublishers.headless.UI.fragment.l) iVar;
                lVar.getClass();
                lVar.E = (com.google.android.material.bottomsheet.h) dialogInterface;
                if (com.google.mlkit.common.internal.model.a.n(lVar.getActivity(), "OT_PConCreateDialog")) {
                    assistantMode.utils.studiableMetadata.b bVar5 = lVar.e1;
                    I iRequireActivity = lVar.requireActivity();
                    com.google.android.material.bottomsheet.h hVar13 = lVar.E;
                    bVar5.getClass();
                    assistantMode.utils.studiableMetadata.b.z(iRequireActivity, hVar13);
                }
                lVar.E.setCancelable(false);
                lVar.E.setCanceledOnTouchOutside(false);
                lVar.E.setOnKeyListener(new f(lVar, 5));
                break;
            case 7:
                com.onetrust.otpublishers.headless.UI.fragment.m mVar2 = (com.onetrust.otpublishers.headless.UI.fragment.m) iVar;
                mVar2.getClass();
                com.google.android.material.bottomsheet.h hVar14 = (com.google.android.material.bottomsheet.h) dialogInterface;
                mVar2.t = hVar14;
                com.google.mlkit.common.internal.model.a aVar = mVar2.F;
                Context context = mVar2.w;
                aVar.getClass();
                com.google.mlkit.common.internal.model.a.g(context, hVar14);
                mVar2.t.setCancelable(false);
                mVar2.t.setCanceledOnTouchOutside(false);
                mVar2.t.setOnKeyListener(new f(mVar2, i3));
                break;
            case 8:
                com.onetrust.otpublishers.headless.UI.fragment.s this$02 = (com.onetrust.otpublishers.headless.UI.fragment.s) iVar;
                Intrinsics.checkNotNullParameter(this$02, "this$0");
                Intrinsics.checkNotNullParameter(dialogInterface, "dialogInterface");
                this$02.x = (com.google.android.material.bottomsheet.h) dialogInterface;
                I activity5 = this$02.getActivity();
                com.google.android.material.bottomsheet.h hVar15 = this$02.x;
                this$02.u.getClass();
                assistantMode.utils.studiableMetadata.b.z(activity5, hVar15);
                com.google.android.material.bottomsheet.h hVar16 = this$02.x;
                if (hVar16 != null) {
                    hVar16.setCancelable(false);
                }
                com.google.android.material.bottomsheet.h hVar17 = this$02.x;
                if (hVar17 != null) {
                    hVar17.setCanceledOnTouchOutside(false);
                }
                if (this$02.requireArguments().containsKey("SDK_LIST_VIEW_TITLE") && (hVar = this$02.x) != null) {
                    hVar.setTitle(this$02.requireArguments().getString("SDK_LIST_VIEW_TITLE"));
                }
                com.google.android.material.bottomsheet.h hVar18 = this$02.x;
                if (hVar18 != null) {
                    hVar18.setOnKeyListener(new f(this$02, 7));
                    break;
                }
                break;
            case 9:
                t tVar = (t) iVar;
                tVar.getClass();
                com.google.android.material.bottomsheet.h hVar19 = (com.google.android.material.bottomsheet.h) dialogInterface;
                tVar.t = hVar19;
                com.google.mlkit.common.internal.model.a aVar2 = tVar.F;
                Context context2 = tVar.w;
                aVar2.getClass();
                com.google.mlkit.common.internal.model.a.g(context2, hVar19);
                tVar.t.setCancelable(false);
                tVar.t.setCanceledOnTouchOutside(false);
                tVar.t.setOnKeyListener(new f(tVar, 8));
                break;
            case 10:
                u uVar = (u) iVar;
                uVar.getClass();
                uVar.y = (com.google.android.material.bottomsheet.h) dialogInterface;
                assistantMode.utils.studiableMetadata.b bVar6 = uVar.G;
                I activity6 = uVar.getActivity();
                com.google.android.material.bottomsheet.h hVar20 = uVar.y;
                bVar6.getClass();
                assistantMode.utils.studiableMetadata.b.z(activity6, hVar20);
                uVar.y.setCancelable(false);
                uVar.y.setCanceledOnTouchOutside(false);
                uVar.y.setOnKeyListener(new f(uVar, 9));
                break;
            case 11:
                v vVar = (v) iVar;
                vVar.getClass();
                vVar.v = (com.google.android.material.bottomsheet.h) dialogInterface;
                assistantMode.utils.studiableMetadata.b bVar7 = vVar.E;
                I activity7 = vVar.getActivity();
                com.google.android.material.bottomsheet.h hVar21 = vVar.v;
                bVar7.getClass();
                assistantMode.utils.studiableMetadata.b.z(activity7, hVar21);
                vVar.v.setCancelable(false);
                vVar.v.setCanceledOnTouchOutside(false);
                vVar.v.setOnKeyListener(new f(vVar, 10));
                break;
            case 12:
                com.google.firebase.perf.logging.b bVar8 = D.D;
                D this$03 = (D) iVar;
                Intrinsics.checkNotNullParameter(this$03, "this$0");
                Intrinsics.checkNotNullParameter(dialogInterface, "dialogInterface");
                com.google.android.material.bottomsheet.h hVar22 = (com.google.android.material.bottomsheet.h) dialogInterface;
                assistantMode.utils.studiableMetadata.b bVar9 = this$03.u;
                I iRequireActivity2 = this$03.requireActivity();
                bVar9.getClass();
                assistantMode.utils.studiableMetadata.b.z(iRequireActivity2, hVar22);
                hVar22.setCancelable(false);
                hVar22.setCanceledOnTouchOutside(false);
                com.onetrust.otpublishers.headless.UI.DataModels.l lVar2 = (com.onetrust.otpublishers.headless.UI.DataModels.l) this$03.X().h.d();
                if (lVar2 != null && (pVar = lVar2.t) != null && (mVar = (androidx.navigation.internal.m) pVar.b) != null) {
                    hVar22.setTitle((String) mVar.g);
                }
                hVar22.setOnKeyListener(new f(this$03, 11));
                break;
            case 13:
                com.onetrust.otpublishers.headless.UI.fragment.I i6 = (com.onetrust.otpublishers.headless.UI.fragment.I) iVar;
                i6.getClass();
                i6.V = (com.google.android.material.bottomsheet.h) dialogInterface;
                assistantMode.utils.studiableMetadata.b bVar10 = i6.B1;
                I activity8 = i6.getActivity();
                com.google.android.material.bottomsheet.h hVar23 = i6.V;
                bVar10.getClass();
                assistantMode.utils.studiableMetadata.b.z(activity8, hVar23);
                i6.V.setCancelable(false);
                com.google.android.material.bottomsheet.h hVar24 = i6.V;
                if (hVar24 != null && (jSONObject3 = i6.Z) != null) {
                    hVar24.setTitle(jSONObject3.optString("name"));
                }
                i6.V.setOnKeyListener(new f(i6, 12));
                break;
            default:
                Intrinsics.d(dialogInterface);
                ((BaseComposeBottomSheetFragment) iVar).getClass();
                View viewFindViewById = ((com.google.android.material.bottomsheet.h) dialogInterface).findViewById(R.id.design_bottom_sheet);
                if (viewFindViewById != null) {
                    viewFindViewById.setBackgroundColor(0);
                    break;
                }
                break;
        }
    }
}
