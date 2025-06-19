package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

import android.app.Dialog;
import android.content.res.Configuration;
import android.os.Bundle;
import android.util.DisplayMetrics;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.activity.RunnableC0043o;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.I;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTConsentInteractionType;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.quizlet.quizletandroid.R;
import java.util.HashMap;

/* loaded from: classes2.dex */
public class g extends com.google.android.material.bottomsheet.i {
    public OTConfiguration A;
    public BottomSheetBehavior q;
    public FrameLayout r;
    public com.google.android.material.bottomsheet.h s;
    public I t;
    public OTPublishersHeadlessSDK u;
    public com.onetrust.otpublishers.headless.Internal.Event.a v;
    public int w;
    public assistantMode.utils.studiableMetadata.b x;
    public int y;
    public a z;

    @Override // com.google.android.material.bottomsheet.i, androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialogK = super.K(bundle);
        dialogK.setOnShowListener(new e(this, 0));
        return dialogK;
    }

    public final void Q(HashMap map, boolean z, boolean z2) {
        assistantMode.utils.studiableMetadata.b bVar = this.x;
        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(12, 4);
        com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.v;
        bVar.getClass();
        assistantMode.utils.studiableMetadata.b.y(mVar, aVar);
        com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = this.v;
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.u;
        OTConfiguration oTConfiguration = this.A;
        s sVar = new s();
        Bundle bundle = new Bundle();
        bundle.putString("TV_PC_CONTENT", OTFragmentTags.OT_VENDOR_LIST_FRAGMENT_TAG);
        sVar.setArguments(bundle);
        sVar.d = aVar2;
        sVar.c = this;
        sVar.b = oTPublishersHeadlessSDK;
        sVar.o = oTPublishersHeadlessSDK.getOtVendorUtils();
        sVar.n = z;
        sVar.m = map;
        sVar.H = OTVendorListMode.IAB;
        sVar.J = oTConfiguration;
        if (z2) {
            sVar.H = OTVendorListMode.GOOGLE;
        }
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        childFragmentManager.getClass();
        C1121a c1121a = new C1121a(childFragmentManager);
        c1121a.l(R.id.tv_main_lyt, sVar, null);
        c1121a.d(OTFragmentTags.OT_VENDOR_LIST_FRAGMENT_TAG);
        c1121a.g();
    }

    public final void R(int i, String str) {
        new Thread(new RunnableC0043o(this, str, i, 7)).start();
        G();
    }

    public final void a() {
        String str;
        int i = this.y;
        String str2 = OTConsentInteractionType.PC_CLOSE;
        if (i == 0) {
            assistantMode.utils.studiableMetadata.b bVar = this.x;
            androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(2, 4);
            com.onetrust.otpublishers.headless.Internal.Event.a aVar = this.v;
            bVar.getClass();
            assistantMode.utils.studiableMetadata.b.y(mVar, aVar);
            str = OTConsentInteractionType.BANNER_CLOSE;
        } else {
            str = OTConsentInteractionType.PC_CLOSE;
        }
        if (this.y == 1) {
            assistantMode.utils.studiableMetadata.b bVar2 = this.x;
            androidx.compose.foundation.lazy.grid.m mVar2 = new androidx.compose.foundation.lazy.grid.m(6, 4);
            com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = this.v;
            bVar2.getClass();
            assistantMode.utils.studiableMetadata.b.y(mVar2, aVar2);
            this.y = 0;
        } else {
            str2 = str;
        }
        if (this.y == 3) {
            assistantMode.utils.studiableMetadata.b bVar3 = this.x;
            androidx.compose.foundation.lazy.grid.m mVar3 = new androidx.compose.foundation.lazy.grid.m(13, 4);
            com.onetrust.otpublishers.headless.Internal.Event.a aVar3 = this.v;
            bVar3.getClass();
            assistantMode.utils.studiableMetadata.b.y(mVar3, aVar3);
            this.y = 0;
        }
        int i2 = this.y;
        if (i2 == 4 || 5 == i2) {
            assistantMode.utils.studiableMetadata.b bVar4 = this.x;
            androidx.compose.foundation.lazy.grid.m mVar4 = new androidx.compose.foundation.lazy.grid.m(13, 4);
            com.onetrust.otpublishers.headless.Internal.Event.a aVar4 = this.v;
            bVar4.getClass();
            assistantMode.utils.studiableMetadata.b.y(mVar4, aVar4);
            this.y = 1;
        }
        if (this.y == 6) {
            assistantMode.utils.studiableMetadata.b bVar5 = this.x;
            androidx.compose.foundation.lazy.grid.m mVar5 = new androidx.compose.foundation.lazy.grid.m(26, 4);
            com.onetrust.otpublishers.headless.Internal.Event.a aVar5 = this.v;
            bVar5.getClass();
            assistantMode.utils.studiableMetadata.b.y(mVar5, aVar5);
            this.y = 1;
        }
        if (!str2.equals(OTConsentInteractionType.BANNER_CLOSE)) {
            getChildFragmentManager().V();
        }
        if (getChildFragmentManager().J() > 1 || str2.equals(OTConsentInteractionType.BANNER_CLOSE)) {
            return;
        }
        androidx.compose.foundation.lazy.grid.m mVar6 = new androidx.compose.foundation.lazy.grid.m(17, 4);
        mVar6.d = str2;
        assistantMode.utils.studiableMetadata.b bVar6 = this.x;
        com.onetrust.otpublishers.headless.Internal.Event.a aVar6 = this.v;
        bVar6.getClass();
        assistantMode.utils.studiableMetadata.b.y(mVar6, aVar6);
        G();
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        com.google.android.material.bottomsheet.h hVar = this.s;
        if (getActivity() != null && hVar == null) {
            OTLogger.c("OTTV", 3, "setupFullHeight: null instance found, recreating bottomSheetDialog");
            hVar = new com.google.android.material.bottomsheet.h(getActivity());
        }
        FrameLayout frameLayout = (FrameLayout) hVar.findViewById(R.id.design_bottom_sheet);
        this.r = frameLayout;
        if (frameLayout != null) {
            this.q = BottomSheetBehavior.C(frameLayout);
            ViewGroup.LayoutParams layoutParams = this.r.getLayoutParams();
            DisplayMetrics displayMetrics = new DisplayMetrics();
            if (getActivity() != null) {
                getActivity().getWindowManager().getDefaultDisplay().getMetrics(displayMetrics);
            } else {
                OTLogger.c("OneTrust", 6, "TV: getActivity() returned null");
            }
            int i = displayMetrics.heightPixels;
            if (layoutParams != null) {
                layoutParams.height = i;
            }
            this.r.setLayoutParams(layoutParams);
            this.q.J(3);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x00c5  */
    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onCreate(android.os.Bundle r9) {
        /*
            Method dump skipped, instructions count: 350
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.fragments.g.onCreate(android.os.Bundle):void");
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        I i = this.t;
        return com.onetrust.otpublishers.headless.Internal.a.o(i) ? layoutInflater.cloneInContext(new androidx.appcompat.view.d(i, R.style.Theme_AppCompat_Light_NoActionBar)).inflate(R.layout.ot_pc_main_tvfragment, viewGroup, false) : layoutInflater.inflate(R.layout.ot_pc_main_tvfragment, viewGroup, false);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final void p(int i) {
        if (i == 14) {
            R(10, OTConsentInteractionType.PC_CONFIRM);
        }
        if (i == 11) {
            R(3, OTConsentInteractionType.BANNER_ALLOW_ALL);
        }
        if (i == 12) {
            R(4, OTConsentInteractionType.BANNER_REJECT_ALL);
        }
        if (i == 21) {
            R(8, OTConsentInteractionType.PC_ALLOW_ALL);
        }
        if (i == 22) {
            R(9, OTConsentInteractionType.PC_REJECT_ALL);
        }
        if (i == 13) {
            R(2, OTConsentInteractionType.BANNER_CLOSE);
        }
        if (i == 16) {
            R(2, OTConsentInteractionType.BANNER_CONTINUE_WITHOUT_ACCEPTING);
        }
        if (i == 15) {
            this.y = 3;
            a aVar = this.z;
            if (aVar != null && aVar.getArguments() != null) {
                this.z.getArguments().putInt("OT_TV_FOCUSED_BTN", 2);
            }
            Q(null, false, false);
        }
        if (i == 17) {
            this.y = 5;
            Q(null, false, false);
        }
        if (i == 18) {
            this.y = 4;
            Q(null, false, true);
        }
        if (i == 32) {
            R(20, OTConsentInteractionType.VENDOR_LIST_REJECT_ALL);
        }
        if (i == 31) {
            R(19, OTConsentInteractionType.VENDOR_LIST_ALLOW_ALL);
        }
        if (i == 33) {
            R(14, OTConsentInteractionType.VENDOR_LIST_CONFIRM);
        }
        if (i == 23) {
            a();
        }
        if (i == 42) {
            R(22, OTConsentInteractionType.SDK_LIST_REJECT_ALL);
        }
        if (i == 41) {
            R(21, OTConsentInteractionType.SDK_LIST_ALLOW_ALL);
        }
        if (i == 43) {
            R(23, OTConsentInteractionType.SDK_LIST_CONFIRM);
        }
    }
}
