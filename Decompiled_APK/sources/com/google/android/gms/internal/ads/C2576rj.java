package com.google.android.gms.internal.ads;

import android.content.Context;
import android.graphics.Rect;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import android.widget.FrameLayout;
import com.amazon.device.ads.DtbDeviceData;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.rj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2576rj implements InterfaceC2389n9 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ C2662tj b;
    public final /* synthetic */ FrameLayout c;
    public final /* synthetic */ WindowManager d;

    public /* synthetic */ C2576rj(C2662tj c2662tj, WindowManager windowManager, FrameLayout frameLayout) {
        this.b = c2662tj;
        this.d = windowManager;
        this.c = frameLayout;
    }

    /* JADX WARN: Type inference failed for: r1v12, types: [com.google.android.gms.internal.ads.sj] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    public final void e(Object obj, Map map) throws NumberFormatException {
        switch (this.a) {
            case 0:
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
                com.google.android.gms.ads.internal.util.client.i.d("Hide native ad policy validator overlay.");
                interfaceC2529qe.N().setVisibility(8);
                if (interfaceC2529qe.N().getWindowToken() != null) {
                    this.d.removeView(interfaceC2529qe.N());
                }
                interfaceC2529qe.destroy();
                ViewTreeObserver viewTreeObserver = this.c.getViewTreeObserver();
                C2662tj c2662tj = this.b;
                if (c2662tj.c != null && viewTreeObserver != null && viewTreeObserver.isAlive()) {
                    viewTreeObserver.removeOnScrollChangedListener(c2662tj.c);
                    break;
                }
                break;
            default:
                final InterfaceC2529qe interfaceC2529qe2 = (InterfaceC2529qe) obj;
                C1669Be c1669BeL = interfaceC2529qe2.L();
                C2662tj c2662tj2 = this.b;
                c1669BeL.g = new Fi(17, c2662tj2, map);
                if (map != null) {
                    final FrameLayout frameLayout = this.c;
                    Context context = frameLayout.getContext();
                    String str = (String) map.get("validator_width");
                    C2601s7 c2601s7 = AbstractC2773w7.c8;
                    com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                    int iB = C2662tj.b(context, str, ((Integer) rVar.c.a(c2601s7)).intValue());
                    String str2 = (String) map.get("validator_height");
                    C2601s7 c2601s72 = AbstractC2773w7.d8;
                    SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
                    int iB2 = C2662tj.b(context, str2, ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).intValue());
                    int iB3 = C2662tj.b(context, (String) map.get("validator_x"), 0);
                    int iB4 = C2662tj.b(context, (String) map.get("validator_y"), 0);
                    interfaceC2529qe2.k0(new com.bumptech.glide.load.engine.cache.f(1, iB, iB2));
                    try {
                        interfaceC2529qe2.n().getSettings().setUseWideViewPort(((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.e8)).booleanValue());
                        interfaceC2529qe2.n().getSettings().setLoadWithOverviewMode(((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.f8)).booleanValue());
                    } catch (NullPointerException unused) {
                    }
                    final WindowManager.LayoutParams layoutParamsC = com.google.android.gms.internal.mlkit_vision_common.W2.c();
                    layoutParamsC.x = iB3;
                    layoutParamsC.y = iB4;
                    View viewN = interfaceC2529qe2.N();
                    final WindowManager windowManager = this.d;
                    windowManager.updateViewLayout(viewN, layoutParamsC);
                    final String str3 = (String) map.get(DtbDeviceData.DEVICE_DATA_ORIENTATION_KEY);
                    Rect rect = new Rect();
                    if (frameLayout.getGlobalVisibleRect(rect)) {
                        final int i = (("1".equals(str3) || "2".equals(str3)) ? rect.bottom : rect.top) - iB4;
                        c2662tj2.c = new ViewTreeObserver.OnScrollChangedListener() { // from class: com.google.android.gms.internal.ads.sj
                            @Override // android.view.ViewTreeObserver.OnScrollChangedListener
                            public final void onScrollChanged() {
                                Rect rect2 = new Rect();
                                if (frameLayout.getGlobalVisibleRect(rect2)) {
                                    InterfaceC2529qe interfaceC2529qe3 = interfaceC2529qe2;
                                    if (interfaceC2529qe3.N().getWindowToken() == null) {
                                        return;
                                    }
                                    String str4 = str3;
                                    boolean zEquals = "1".equals(str4);
                                    WindowManager.LayoutParams layoutParams = layoutParamsC;
                                    int i2 = i;
                                    if (zEquals || "2".equals(str4)) {
                                        layoutParams.y = rect2.bottom - i2;
                                    } else {
                                        layoutParams.y = rect2.top - i2;
                                    }
                                    windowManager.updateViewLayout(interfaceC2529qe3.N(), layoutParams);
                                }
                            }
                        };
                        ViewTreeObserver viewTreeObserver2 = frameLayout.getViewTreeObserver();
                        if (viewTreeObserver2 != null && viewTreeObserver2.isAlive()) {
                            viewTreeObserver2.addOnScrollChangedListener(c2662tj2.c);
                        }
                    }
                    String str4 = (String) map.get("overlay_url");
                    if (!TextUtils.isEmpty(str4)) {
                        interfaceC2529qe2.loadUrl(str4);
                        break;
                    }
                }
                break;
        }
    }

    public /* synthetic */ C2576rj(C2662tj c2662tj, FrameLayout frameLayout, WindowManager windowManager) {
        this.b = c2662tj;
        this.c = frameLayout;
        this.d = windowManager;
    }
}
