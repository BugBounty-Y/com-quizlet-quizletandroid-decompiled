package com.google.android.gms.internal.ads;

import android.content.Context;
import android.view.View;
import android.view.WindowManager;
import android.widget.FrameLayout;
import com.google.android.gms.ads.internal.client.C1614q;
import java.lang.ref.WeakReference;

/* renamed from: com.google.android.gms.internal.ads.tj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2662tj {
    public final C2406nk a;
    public final C1843ak b;
    public ViewTreeObserverOnScrollChangedListenerC2619sj c = null;

    public C2662tj(C2406nk c2406nk, C1843ak c1843ak) {
        this.a = c2406nk;
        this.b = c1843ak;
    }

    public static final int b(Context context, String str, int i) throws NumberFormatException {
        try {
            i = Integer.parseInt(str);
        } catch (NumberFormatException unused) {
        }
        com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
        return com.google.android.gms.ads.internal.util.client.c.n(context, i);
    }

    public final View a(FrameLayout frameLayout, WindowManager windowManager) {
        InterfaceC2529qe interfaceC2529qeA = this.a.a(com.google.android.gms.ads.internal.client.zzr.b(), null, null);
        interfaceC2529qeA.N().setVisibility(4);
        interfaceC2529qeA.N().setContentDescription("policy_validator");
        interfaceC2529qeA.O0("/sendMessageToSdk", new C1956d9(this, 7));
        interfaceC2529qeA.O0("/hideValidatorOverlay", new C2576rj(this, windowManager, frameLayout));
        interfaceC2529qeA.O0("/open", new C2689u9(null, null, null, null, null));
        WeakReference weakReference = new WeakReference(interfaceC2529qeA);
        C2576rj c2576rj = new C2576rj(this, frameLayout, windowManager);
        C1843ak c1843ak = this.b;
        c1843ak.c("/loadNativeAdPolicyViolations", new Ji(c1843ak, weakReference, "/loadNativeAdPolicyViolations", c2576rj));
        c1843ak.c("/showValidatorOverlay", new Ji(c1843ak, new WeakReference(interfaceC2529qeA), "/showValidatorOverlay", new C2175i9(27)));
        return interfaceC2529qeA.N();
    }
}
