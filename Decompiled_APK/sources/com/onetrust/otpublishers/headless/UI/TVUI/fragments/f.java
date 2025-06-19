package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

import android.content.DialogInterface;
import android.view.KeyEvent;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3665l4;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.OTConsentInteractionType;
import com.onetrust.otpublishers.headless.UI.fragment.C4063g;
import com.onetrust.otpublishers.headless.UI.fragment.D;
import com.onetrust.otpublishers.headless.UI.fragment.I;
import com.onetrust.otpublishers.headless.UI.fragment.ViewOnClickListenerC4064h;
import com.onetrust.otpublishers.headless.UI.fragment.ViewOnClickListenerC4065i;
import com.onetrust.otpublishers.headless.UI.fragment.t;
import com.onetrust.otpublishers.headless.UI.fragment.u;
import com.onetrust.otpublishers.headless.UI.fragment.v;
import com.onetrust.otpublishers.headless.UI.fragment.w;
import com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements DialogInterface.OnKeyListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ DialogInterfaceOnCancelListenerC1151t b;

    public /* synthetic */ f(DialogInterfaceOnCancelListenerC1151t dialogInterfaceOnCancelListenerC1151t, int i) {
        this.a = i;
        this.b = dialogInterfaceOnCancelListenerC1151t;
    }

    /* JADX WARN: Type inference failed for: r8v32, types: [com.google.android.material.bottomsheet.i, com.onetrust.otpublishers.headless.UI.a] */
    @Override // android.content.DialogInterface.OnKeyListener
    public final boolean onKey(DialogInterface dialogInterface, int i, KeyEvent event) throws JSONException {
        DialogInterfaceOnCancelListenerC1151t dialogInterfaceOnCancelListenerC1151t = this.b;
        switch (this.a) {
            case 0:
                g gVar = (g) dialogInterfaceOnCancelListenerC1151t;
                gVar.getClass();
                if (i == 4 && event.getAction() == 1) {
                    gVar.a();
                    break;
                }
                break;
            case 1:
                com.google.firebase.heartbeatinfo.e eVar = C4063g.A;
                C4063g this$0 = (C4063g) dialogInterfaceOnCancelListenerC1151t;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                Intrinsics.checkNotNullParameter(event, "event");
                if (i == 4 && event.getAction() == 1) {
                    OTConfiguration oTConfiguration = this$0.u;
                    if (oTConfiguration != null && !oTConfiguration.isBannerBackButtonDisabled()) {
                        OTConfiguration oTConfiguration2 = this$0.u;
                        Intrinsics.d(oTConfiguration2);
                        if (oTConfiguration2.isBannerBackButtonDisMissUI()) {
                            this$0.S(OTConsentInteractionType.BANNER_BACK, false);
                        } else {
                            OTConfiguration oTConfiguration3 = this$0.u;
                            Intrinsics.d(oTConfiguration3);
                            if (oTConfiguration3.isBannerBackButtonCloseBanner()) {
                                this$0.S(OTConsentInteractionType.BANNER_CLOSE, true);
                            }
                        }
                        break;
                    } else {
                        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(18, 4);
                        mVar.d = OTConsentInteractionType.BANNER_BACK;
                        com.onetrust.otpublishers.headless.Internal.Event.a aVar = this$0.t;
                        this$0.x.getClass();
                        assistantMode.utils.studiableMetadata.b.y(mVar, aVar);
                        break;
                    }
                }
                break;
            case 2:
                ViewOnClickListenerC4064h viewOnClickListenerC4064h = (ViewOnClickListenerC4064h) dialogInterfaceOnCancelListenerC1151t;
                viewOnClickListenerC4064h.getClass();
                if (i == 4 && event.getAction() == 1) {
                    viewOnClickListenerC4064h.G();
                    w wVar = viewOnClickListenerC4064h.F;
                    wVar.getClass();
                    com.google.firebase.perf.logging.b bVar = D.D;
                    D this$02 = wVar.a;
                    Intrinsics.checkNotNullParameter(this$02, "this$0");
                    this$02.X().D();
                    break;
                }
                break;
            case 3:
                ViewOnClickListenerC4065i viewOnClickListenerC4065i = (ViewOnClickListenerC4065i) dialogInterfaceOnCancelListenerC1151t;
                viewOnClickListenerC4065i.getClass();
                if (i == 4 && event.getAction() == 1) {
                    viewOnClickListenerC4065i.G();
                    break;
                }
                break;
            case 4:
                com.onetrust.otpublishers.headless.UI.fragment.k kVar = (com.onetrust.otpublishers.headless.UI.fragment.k) dialogInterfaceOnCancelListenerC1151t;
                kVar.getClass();
                if (event.getAction() == 1 && i == 4) {
                    kVar.G();
                    com.onetrust.otpublishers.headless.UI.adapter.m mVar2 = kVar.f1;
                    if (mVar2 != null) {
                        mVar2.p(4);
                        break;
                    }
                }
                break;
            case 5:
                com.onetrust.otpublishers.headless.UI.fragment.l lVar = (com.onetrust.otpublishers.headless.UI.fragment.l) dialogInterfaceOnCancelListenerC1151t;
                lVar.getClass();
                if (i == 4 && event.getAction() == 1) {
                    assistantMode.utils.studiableMetadata.b bVar2 = lVar.e1;
                    androidx.compose.foundation.lazy.grid.m mVar3 = new androidx.compose.foundation.lazy.grid.m(6, 4);
                    com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = lVar.c1;
                    bVar2.getClass();
                    assistantMode.utils.studiableMetadata.b.y(mVar3, aVar2);
                    lVar.Q(2, true);
                    break;
                }
                break;
            case 6:
                com.onetrust.otpublishers.headless.UI.fragment.m mVar4 = (com.onetrust.otpublishers.headless.UI.fragment.m) dialogInterfaceOnCancelListenerC1151t;
                mVar4.getClass();
                if (i == 4 && event.getAction() == 1) {
                    mVar4.B = mVar4.A;
                    mVar4.G();
                    break;
                }
                break;
            case 7:
                com.onetrust.otpublishers.headless.UI.fragment.s this$03 = (com.onetrust.otpublishers.headless.UI.fragment.s) dialogInterfaceOnCancelListenerC1151t;
                Intrinsics.checkNotNullParameter(this$03, "this$0");
                Intrinsics.checkNotNullParameter(event, "event");
                if (i == 4 && event.getAction() == 1) {
                    this$03.a();
                    break;
                }
                break;
            case 8:
                t tVar = (t) dialogInterfaceOnCancelListenerC1151t;
                tVar.getClass();
                if (i == 4 && event.getAction() == 1) {
                    tVar.B = tVar.A;
                    tVar.G();
                    break;
                }
                break;
            case 9:
                u uVar = (u) dialogInterfaceOnCancelListenerC1151t;
                uVar.getClass();
                if (i == 4 && event.getAction() == 1) {
                    uVar.G();
                    break;
                }
                break;
            case 10:
                v vVar = (v) dialogInterfaceOnCancelListenerC1151t;
                vVar.getClass();
                if (i == 4 && event.getAction() == 1) {
                    vVar.D.a(new androidx.compose.foundation.lazy.grid.m(6, 4));
                    vVar.G();
                    break;
                }
                break;
            case 11:
                com.google.firebase.perf.logging.b bVar3 = D.D;
                D this$04 = (D) dialogInterfaceOnCancelListenerC1151t;
                Intrinsics.checkNotNullParameter(this$04, "this$0");
                Intrinsics.checkNotNullParameter(event, "event");
                if (i == 4 && event.getAction() == 1) {
                    assistantMode.utils.studiableMetadata.b bVar4 = this$04.u;
                    androidx.compose.foundation.lazy.grid.m mVar5 = new androidx.compose.foundation.lazy.grid.m(13, 4);
                    com.onetrust.otpublishers.headless.Internal.Event.a aVar3 = this$04.s;
                    bVar4.getClass();
                    assistantMode.utils.studiableMetadata.b.y(mVar5, aVar3);
                    this$04.G();
                    ?? r8 = this$04.v;
                    if (r8 != 0) {
                        r8.p(3);
                    }
                    ((Map) AbstractC3665l4.a(this$04.X().k)).clear();
                    break;
                }
                break;
            case 12:
                I i2 = (I) dialogInterfaceOnCancelListenerC1151t;
                i2.getClass();
                if (event.getAction() == 1 && i == 4) {
                    i2.G();
                    w wVar2 = i2.q1;
                    if (wVar2 != null) {
                        com.google.firebase.perf.logging.b bVar5 = D.D;
                        D this$05 = wVar2.a;
                        Intrinsics.checkNotNullParameter(this$05, "this$0");
                        this$05.X().D();
                        break;
                    }
                }
                break;
            default:
                if (i == 4 && event.getAction() == 1) {
                    FullScreenConvertibleModalDialogFragment fullScreenConvertibleModalDialogFragment = (FullScreenConvertibleModalDialogFragment) dialogInterfaceOnCancelListenerC1151t;
                    if (fullScreenConvertibleModalDialogFragment.getChildFragmentManager().J() == 0) {
                        fullScreenConvertibleModalDialogFragment.H(false, false);
                    } else {
                        fullScreenConvertibleModalDialogFragment.getChildFragmentManager().W();
                    }
                    break;
                }
                break;
        }
        return false;
    }
}
