package com.google.android.gms.internal.mlkit_vision_common;

import android.app.KeyguardManager;
import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.ImageView;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.AbstractC2930zt;
import com.google.android.gms.internal.ads.At;
import com.google.android.gms.internal.ads.C2501pt;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.C2883yp;
import com.google.android.gms.internal.ads.SharedPreferencesOnSharedPreferenceChangeListenerC2687u7;
import com.google.android.gms.internal.ads.Vp;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4392k;
import com.quizlet.features.settings.viewmodels.C4449g;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class W2 {
    public static final void a(C4449g c4449g, Function0 onUpAction, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C4449g c4449g2;
        Intrinsics.checkNotNullParameter(onUpAction, "onUpAction");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-454129190);
        int i3 = i | 2 | (c0814p.h(onUpAction) ? 32 : 16);
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            c4449g2 = c4449g;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                androidx.lifecycle.w0 w0VarE = AbstractC3417z1.e(C4449g.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p = c0814p;
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-15);
                c4449g2 = (C4449g) w0VarE;
            } else {
                c0814p.Q();
                i2 = i3 & (-15);
                c4449g2 = c4449g;
            }
            c0814p.q();
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(c4449g2.f, c0814p);
            Object[] objArr = new Object[0];
            c0814p.X(636773217);
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (objI == obj) {
                objI = new C4392k(29);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            kotlinx.coroutines.flow.d0 d0Var = c4449g2.b;
            c0814p.X(636775867);
            boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI2 = c0814p.I();
            if (z || objI2 == obj) {
                objI2 = new com.quizlet.features.settings.composables.changeusername.f(onUpAction, null);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI2, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI3 = c0814p.I();
            if (zF || objI3 == obj) {
                objI3 = new com.quizlet.features.settings.composables.changeusername.e(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            com.quizlet.features.settings.data.states.l lVar = (com.quizlet.features.settings.data.states.l) AbstractC4178x.k(unit, (Function2) objI3, c0814p, false, interfaceC0773a0M);
            String str = (String) interfaceC0773a0.getValue();
            c0814p.X(636781041);
            boolean zH = c0814p.h(c4449g2) | c0814p.f(interfaceC0773a0);
            Object objI4 = c0814p.I();
            if (zH || objI4 == obj) {
                objI4 = new com.quizlet.features.settings.composables.changeusername.a(c4449g2, interfaceC0773a0, 0);
                c0814p.i0(objI4);
            }
            Function0 function0 = (Function0) objI4;
            boolean zR = AbstractC4178x.r(c0814p, false, 636783443, interfaceC0773a0);
            Object objI5 = c0814p.I();
            if (zR || objI5 == obj) {
                objI5 = new com.quizlet.assembly.compose.modals.t(interfaceC0773a0, 18);
                c0814p.i0(objI5);
            }
            c0814p.p(false);
            b(lVar, str, onUpAction, function0, (Function1) objI5, c0814p, (i2 << 3) & 896, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.changeusername.b(c4449g2, onUpAction, i, 0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0046  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x004b  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0081  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0099  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00ab  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00ad  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00b7  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00d4  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x00ef  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0110  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0139  */
    /* JADX WARN: Removed duplicated region for block: B:89:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(com.quizlet.features.settings.data.states.l r20, java.lang.String r21, kotlin.jvm.functions.Function0 r22, kotlin.jvm.functions.Function0 r23, kotlin.jvm.functions.Function1 r24, androidx.compose.runtime.InterfaceC0806l r25, int r26, int r27) {
        /*
            Method dump skipped, instructions count: 328
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.W2.b(com.quizlet.features.settings.data.states.l, java.lang.String, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static WindowManager.LayoutParams c() {
        WindowManager.LayoutParams layoutParams = new WindowManager.LayoutParams(-2, -2, 0, 0, -2);
        layoutParams.flags = ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.a8)).intValue();
        layoutParams.type = 2;
        layoutParams.gravity = 8388659;
        return layoutParams;
    }

    public static JSONObject d(String str, Context context, Point point, Point point2) throws JSONException {
        JSONObject jSONObject;
        JSONObject jSONObject2 = null;
        try {
            jSONObject = new JSONObject();
        } catch (Exception e) {
            e = e;
        }
        try {
            JSONObject jSONObject3 = new JSONObject();
            try {
                int i = point2.x;
                C1614q c1614q = C1614q.f;
                jSONObject3.put("x", c1614q.a.f(context, i));
                jSONObject3.put("y", c1614q.a.f(context, point2.y));
                jSONObject3.put("start_x", c1614q.a.f(context, point.x));
                jSONObject3.put("start_y", c1614q.a.f(context, point.y));
                jSONObject2 = jSONObject3;
            } catch (JSONException e2) {
                com.google.android.gms.ads.internal.util.client.i.f("Error occurred while putting signals into JSON object.", e2);
            }
            jSONObject.put("click_point", jSONObject2);
            jSONObject.put("asset_id", str);
            return jSONObject;
        } catch (Exception e3) {
            e = e3;
            jSONObject2 = jSONObject;
            com.google.android.gms.ads.internal.util.client.i.f("Error occurred while grabbing click signals.", e);
            return jSONObject2;
        }
    }

    public static JSONObject e(Context context, Map map, Map map2, View view, ImageView.ScaleType scaleType) throws JSONException {
        String str;
        int[] iArr;
        JSONObject jSONObject;
        String str2 = "ad_view";
        JSONObject jSONObject2 = new JSONObject();
        if (map != null && view != null) {
            int i = 2;
            int[] iArr2 = new int[2];
            view.getLocationOnScreen(iArr2);
            Iterator it2 = map.entrySet().iterator();
            while (it2.hasNext()) {
                Map.Entry entry = (Map.Entry) it2.next();
                View view2 = (View) ((WeakReference) entry.getValue()).get();
                if (view2 != null) {
                    int[] iArr3 = new int[i];
                    view2.getLocationOnScreen(iArr3);
                    JSONObject jSONObject3 = new JSONObject();
                    JSONObject jSONObject4 = new JSONObject();
                    Iterator it3 = it2;
                    try {
                        int measuredWidth = view2.getMeasuredWidth();
                        iArr = iArr2;
                        try {
                            C1614q c1614q = C1614q.f;
                            com.google.android.gms.ads.internal.util.client.c cVar = c1614q.a;
                            com.google.android.gms.ads.internal.util.client.c cVar2 = c1614q.a;
                            jSONObject4.put(OTUXParamsKeys.OT_UX_WIDTH, cVar.f(context, measuredWidth));
                            jSONObject4.put(OTUXParamsKeys.OT_UX_HEIGHT, cVar2.f(context, view2.getMeasuredHeight()));
                            jSONObject4.put("x", cVar2.f(context, iArr3[0] - iArr[0]));
                            jSONObject4.put("y", cVar2.f(context, iArr3[1] - iArr[1]));
                            jSONObject4.put("relative_to", str2);
                            jSONObject3.put("frame", jSONObject4);
                            Rect rect = new Rect();
                            if (view2.getLocalVisibleRect(rect)) {
                                jSONObject = l(context, rect);
                            } else {
                                jSONObject = new JSONObject();
                                jSONObject.put(OTUXParamsKeys.OT_UX_WIDTH, 0);
                                jSONObject.put(OTUXParamsKeys.OT_UX_HEIGHT, 0);
                                jSONObject.put("x", cVar2.f(context, iArr3[0] - iArr[0]));
                                jSONObject.put("y", cVar2.f(context, iArr3[1] - iArr[1]));
                                jSONObject.put("relative_to", str2);
                            }
                            jSONObject3.put("visible_bounds", jSONObject);
                            if (((String) entry.getKey()).equals("3010")) {
                                C2601s7 c2601s7 = AbstractC2773w7.V7;
                                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                                SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
                                SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u72 = rVar.c;
                                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s7)).booleanValue()) {
                                    jSONObject3.put("mediaview_graphics_matrix", view2.getMatrix().toShortString());
                                }
                                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(AbstractC2773w7.W7)).booleanValue()) {
                                    ViewGroup.LayoutParams layoutParams = view2.getLayoutParams();
                                    jSONObject3.put("view_width_layout_type", m(layoutParams.width) - 1);
                                    jSONObject3.put("view_height_layout_type", m(layoutParams.height) - 1);
                                }
                                if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(AbstractC2773w7.X7)).booleanValue()) {
                                    ArrayList arrayList = new ArrayList();
                                    arrayList.add(Integer.valueOf(view2.getId()));
                                    for (ViewParent parent = view2.getParent(); parent instanceof View; parent = parent.getParent()) {
                                        arrayList.add(Integer.valueOf(((View) parent).getId()));
                                    }
                                    jSONObject3.put("view_path", TextUtils.join("/", arrayList));
                                }
                                if (scaleType != null) {
                                    jSONObject3.put("mediaview_scale_type", scaleType.ordinal());
                                }
                            }
                            if (view2 instanceof TextView) {
                                TextView textView = (TextView) view2;
                                jSONObject3.put("text_color", textView.getCurrentTextColor());
                                str = str2;
                                try {
                                    jSONObject3.put("font_size", textView.getTextSize());
                                    jSONObject3.put("text", textView.getText());
                                } catch (JSONException unused) {
                                    com.google.android.gms.ads.internal.util.client.i.h("Unable to get asset views information");
                                    it2 = it3;
                                    str2 = str;
                                    iArr2 = iArr;
                                    i = 2;
                                }
                            } else {
                                str = str2;
                            }
                            jSONObject3.put("is_clickable", map2 != null && map2.containsKey(entry.getKey()) && view2.isClickable());
                            jSONObject2.put((String) entry.getKey(), jSONObject3);
                        } catch (JSONException unused2) {
                            str = str2;
                        }
                    } catch (JSONException unused3) {
                        str = str2;
                        iArr = iArr2;
                    }
                    it2 = it3;
                    str2 = str;
                    iArr2 = iArr;
                    i = 2;
                }
            }
        }
        return jSONObject2;
    }

    public static JSONObject f(Context context, View view) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        if (view != null) {
            try {
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                jSONObject.put("can_show_on_lock_screen", com.google.android.gms.ads.internal.util.F.E(view));
                boolean z = false;
                if (context != null) {
                    Object systemService = context.getSystemService("keyguard");
                    KeyguardManager keyguardManager = (systemService == null || !(systemService instanceof KeyguardManager)) ? null : (KeyguardManager) systemService;
                    if (keyguardManager != null && keyguardManager.isKeyguardLocked()) {
                        z = true;
                    }
                }
                jSONObject.put("is_keyguard_locked", z);
                return jSONObject;
            } catch (JSONException unused) {
                com.google.android.gms.ads.internal.util.client.i.h("Unable to get lock screen information");
            }
        }
        return jSONObject;
    }

    public static JSONObject g(Context context) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        WindowManager windowManager = (WindowManager) context.getSystemService("window");
        DisplayMetrics displayMetrics = new DisplayMetrics();
        windowManager.getDefaultDisplay().getMetrics(displayMetrics);
        try {
            int i = displayMetrics.widthPixels;
            C1614q c1614q = C1614q.f;
            jSONObject.put(OTUXParamsKeys.OT_UX_WIDTH, c1614q.a.f(context, i));
            jSONObject.put(OTUXParamsKeys.OT_UX_HEIGHT, c1614q.a.f(context, displayMetrics.heightPixels));
            return jSONObject;
        } catch (JSONException unused) {
            return null;
        }
    }

    public static JSONObject h(View view) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        if (view != null) {
            try {
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U7)).booleanValue()) {
                    com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                    ViewParent parent = view.getParent();
                    while (parent != null && !(parent instanceof ScrollView)) {
                        parent = parent.getParent();
                    }
                    jSONObject.put("contained_in_scroll_view", parent != null);
                    return jSONObject;
                }
                com.google.android.gms.ads.internal.util.F f2 = com.google.android.gms.ads.internal.j.C.c;
                ViewParent parent2 = view.getParent();
                while (parent2 != null && !(parent2 instanceof AdapterView)) {
                    parent2 = parent2.getParent();
                }
                if ((parent2 == null ? -1 : ((AdapterView) parent2).getPositionForView(view)) == -1) {
                    z = false;
                }
                jSONObject.put("contained_in_scroll_view", z);
            } catch (Exception unused) {
            }
        }
        return jSONObject;
    }

    /* JADX WARN: Can't wrap try/catch for region: R(6:(2:75|24)|33|67|34|35|(7:37|(1:42)(1:46)|47|(2:49|(1:51)(1:54))(1:55)|66|58|(2:73|60))(7:43|(1:45)(0)|47|(0)(0)|66|58|(0))) */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x0145, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x0152, code lost:
    
        com.google.android.gms.ads.internal.util.client.i.f("Could not log native template signal to JSON", r0);
     */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0111  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x011d  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x012e  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0138  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x013d  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x014c A[Catch: JSONException -> 0x0145, TRY_LEAVE, TryCatch #0 {JSONException -> 0x0145, blocks: (B:34:0x0114, B:51:0x0141, B:54:0x0147, B:55:0x014c), top: B:67:0x0114 }] */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0169 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00f5 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static org.json.JSONObject i(android.content.Context r17, android.view.View r18) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 396
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.W2.i(android.content.Context, android.view.View):org.json.JSONObject");
    }

    public static boolean j(Context context, Vp vp) {
        AbstractC2930zt abstractC2930zt;
        if (!vp.N) {
            return false;
        }
        C2601s7 c2601s7 = AbstractC2773w7.Y7;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        if (zBooleanValue) {
            return ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.b8)).booleanValue();
        }
        String str = (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.Z7);
        if (str.isEmpty() || context == null) {
            return false;
        }
        String packageName = context.getPackageName();
        C2883yp c2883ypE = C2883yp.e(new C2501pt(';'));
        Iterator itE = ((At) c2883ypE.b).e(c2883ypE, str);
        do {
            abstractC2930zt = (AbstractC2930zt) itE;
            if (!abstractC2930zt.hasNext()) {
                return false;
            }
        } while (!((String) abstractC2930zt.next()).equals(packageName));
        return true;
    }

    public static boolean k(int i) {
        C2601s7 c2601s7 = AbstractC2773w7.C3;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            return ((Boolean) rVar.c.a(AbstractC2773w7.D3)).booleanValue() || i <= 15299999;
        }
        return true;
    }

    public static JSONObject l(Context context, Rect rect) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        int i = rect.right - rect.left;
        C1614q c1614q = C1614q.f;
        jSONObject.put(OTUXParamsKeys.OT_UX_WIDTH, c1614q.a.f(context, i));
        int i2 = rect.bottom - rect.top;
        com.google.android.gms.ads.internal.util.client.c cVar = c1614q.a;
        jSONObject.put(OTUXParamsKeys.OT_UX_HEIGHT, cVar.f(context, i2));
        jSONObject.put("x", cVar.f(context, rect.left));
        jSONObject.put("y", cVar.f(context, rect.top));
        jSONObject.put("relative_to", "self");
        return jSONObject;
    }

    public static int m(int i) {
        if (i != -2) {
            return i != -1 ? 2 : 3;
        }
        return 4;
    }
}
