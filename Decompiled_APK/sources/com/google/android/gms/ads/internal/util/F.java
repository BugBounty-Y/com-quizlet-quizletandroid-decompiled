package com.google.android.gms.ads.internal.util;

import android.R;
import android.app.Activity;
import android.app.ActivityManager;
import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.graphics.Rect;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import android.os.PowerManager;
import android.os.Process;
import android.os.RemoteException;
import android.text.TextUtils;
import android.view.View;
import android.view.Window;
import android.webkit.WebSettings;
import com.comscore.android.id.IdHelperAndroid;
import com.facebook.internal.C1549d;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.nativead.NativeAdView;
import com.google.android.gms.internal.ads.AbstractC2009ec;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.AbstractC2930zt;
import com.google.android.gms.internal.ads.At;
import com.google.android.gms.internal.ads.C1693Fe;
import com.google.android.gms.internal.ads.C2492pk;
import com.google.android.gms.internal.ads.C2501pt;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.C2883yp;
import com.google.android.gms.internal.ads.Fi;
import com.google.android.gms.internal.ads.Fk;
import com.google.android.gms.internal.ads.Hk;
import com.google.android.gms.internal.ads.InterfaceC2529qe;
import com.google.android.gms.internal.ads.SharedPreferencesOnSharedPreferenceChangeListenerC2687u7;
import com.google.android.gms.internal.ads.Vp;
import com.google.android.gms.internal.ads.Xp;
import com.google.android.gms.internal.mlkit_vision_common.X2;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.InvocationTargetException;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class F {
    public static final B l = new B(Looper.getMainLooper(), 0);
    public String g;
    public volatile String h;
    public final AtomicReference a = new AtomicReference(null);
    public final AtomicReference b = new AtomicReference(null);
    public final AtomicReference c = new AtomicReference(new Bundle());
    public final AtomicBoolean d = new AtomicBoolean();
    public boolean e = true;
    public final Object f = new Object();
    public boolean i = false;
    public boolean j = false;
    public final ExecutorService k = Executors.newSingleThreadExecutor();

    /* JADX WARN: Code restructure failed: missing block: B:17:0x006b, code lost:
    
        if (com.google.android.gms.ads.internal.util.client.c.l() != false) goto L29;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int D(android.content.Context r7, android.net.Uri r8) {
        /*
            if (r7 != 0) goto L9
            java.lang.String r7 = "Trying to open chrome custom tab on a null context"
            com.google.android.gms.ads.internal.util.A.l(r7)
            r7 = 3
            return r7
        L9:
            boolean r0 = r7 instanceof android.app.Activity
            r1 = 268435456(0x10000000, float:2.524355E-29)
            java.lang.String r2 = "android.intent.action.VIEW"
            if (r0 != 0) goto L21
            android.content.Intent r0 = new android.content.Intent
            r0.<init>(r2)
            r0.setData(r8)
            r0.addFlags(r1)
            r7.startActivity(r0)
            r7 = 2
            return r7
        L21:
            com.google.android.gms.internal.ads.s7 r0 = com.google.android.gms.internal.ads.AbstractC2773w7.E4
            com.google.android.gms.ads.internal.client.r r3 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r4 = r3.c
            java.lang.Object r0 = r4.a(r0)
            java.lang.Boolean r0 = (java.lang.Boolean) r0
            boolean r0 = r0.booleanValue()
            com.google.android.gms.internal.ads.u7 r3 = r3.c
            r4 = 5
            if (r0 == 0) goto L7d
            androidx.browser.customtabs.k r0 = new androidx.browser.customtabs.k
            com.google.android.gms.ads.internal.j r1 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.internal.ads.F7 r1 = r1.n
            androidx.work.impl.model.n r2 = r1.e
            if (r2 != 0) goto L4c
            com.google.android.gms.internal.ads.jd r2 = com.google.android.gms.internal.ads.AbstractC2270kd.a
            com.google.android.gms.internal.ads.e r5 = new com.google.android.gms.internal.ads.e
            r6 = 11
            r5.<init>(r1, r6)
            r2.execute(r5)
        L4c:
            androidx.work.impl.model.n r1 = r1.e
            r0.<init>(r1)
            androidx.work.impl.model.c r0 = r0.c()
            com.google.android.gms.internal.ads.s7 r1 = com.google.android.gms.internal.ads.AbstractC2773w7.Q4
            java.lang.Object r1 = r3.a(r1)
            java.lang.Boolean r1 = (java.lang.Boolean) r1
            boolean r1 = r1.booleanValue()
            if (r1 == 0) goto L6e
            com.google.android.gms.ads.internal.client.q r1 = com.google.android.gms.ads.internal.client.C1614q.f
            com.google.android.gms.ads.internal.util.client.c r1 = r1.a
            boolean r1 = com.google.android.gms.ads.internal.util.client.c.l()
            if (r1 == 0) goto L6e
            goto Laf
        L6e:
            java.lang.Object r1 = r0.b
            android.content.Intent r1 = (android.content.Intent) r1
            java.lang.String r2 = com.google.android.gms.internal.ads.AbstractC2025es.i(r7)
            r1.setPackage(r2)
            r0.v(r7, r8)
            return r4
        L7d:
            com.google.android.gms.internal.ads.s7 r0 = com.google.android.gms.internal.ads.AbstractC2773w7.C4
            java.lang.Object r0 = r3.a(r0)
            java.lang.Boolean r0 = (java.lang.Boolean) r0
            boolean r0 = r0.booleanValue()
            if (r0 == 0) goto Lb0
            com.google.android.gms.internal.ads.G7 r0 = new com.google.android.gms.internal.ads.G7
            r0.<init>()
            io.ktor.client.plugins.api.d r1 = new io.ktor.client.plugins.api.d
            r2 = 5
            r1.<init>(r0, r7, r8, r2)
            r0.d = r1
            android.app.Activity r7 = (android.app.Activity) r7
            androidx.browser.customtabs.l r8 = r0.b
            if (r8 == 0) goto L9f
            goto Laf
        L9f:
            java.lang.String r8 = com.google.android.gms.internal.ads.AbstractC2025es.i(r7)
            if (r8 == 0) goto Laf
            androidx.browser.customtabs.b r1 = new androidx.browser.customtabs.b
            r1.<init>(r0)
            r0.c = r1
            androidx.browser.customtabs.l.a(r7, r8, r1)
        Laf:
            return r4
        Lb0:
            android.content.Intent r0 = new android.content.Intent
            r0.<init>(r2)
            r0.setData(r8)
            r0.addFlags(r1)
            r7.startActivity(r0)
            r7 = 9
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.util.F.D(android.content.Context, android.net.Uri):int");
    }

    /* JADX WARN: Removed duplicated region for block: B:4:0x0007  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean E(android.view.View r2) {
        /*
            android.view.View r2 = r2.getRootView()
            r0 = 0
            if (r2 != 0) goto L9
        L7:
            r2 = r0
            goto L13
        L9:
            android.content.Context r2 = r2.getContext()
            boolean r1 = r2 instanceof android.app.Activity
            if (r1 == 0) goto L7
            android.app.Activity r2 = (android.app.Activity) r2
        L13:
            r1 = 0
            if (r2 != 0) goto L17
            return r1
        L17:
            android.view.Window r2 = r2.getWindow()
            if (r2 != 0) goto L1e
            goto L22
        L1e:
            android.view.WindowManager$LayoutParams r0 = r2.getAttributes()
        L22:
            if (r0 == 0) goto L2d
            int r2 = r0.flags
            r0 = 524288(0x80000, float:7.34684E-40)
            r2 = r2 & r0
            if (r2 == 0) goto L2d
            r2 = 1
            return r2
        L2d:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.util.F.E(android.view.View):boolean");
    }

    public static final void F(Context context, Intent intent) {
        if (intent == null) {
            return;
        }
        Bundle extras = intent.getExtras() != null ? intent.getExtras() : new Bundle();
        extras.putBinder("android.support.customtabs.extra.SESSION", null);
        extras.putString("com.android.browser.application_id", context.getPackageName());
        intent.putExtras(extras);
    }

    public static final String G(Context context) {
        if (context.getApplicationContext() != null) {
            context = context.getApplicationContext();
        }
        return v(u(context));
    }

    public static final String H() {
        StringBuilder sbL = androidx.compose.ui.node.B.l(256, "Mozilla/5.0 (Linux; U; Android");
        String str = Build.VERSION.RELEASE;
        if (str != null) {
            sbL.append(" ");
            sbL.append(str);
        }
        sbL.append("; ");
        sbL.append(Locale.getDefault());
        String str2 = Build.DEVICE;
        if (str2 != null) {
            sbL.append("; ");
            sbL.append(str2);
            String str3 = Build.DISPLAY;
            if (str3 != null) {
                sbL.append(" Build/");
                sbL.append(str3);
            }
        }
        sbL.append(") AppleWebKit/533 Version/4.0 Safari/533");
        return sbL.toString();
    }

    public static final String I() {
        String str = Build.MANUFACTURER;
        String str2 = Build.MODEL;
        return str2.startsWith(str) ? str2 : android.support.v4.media.session.a.l(str, " ", str2);
    }

    public static final HashMap J(String str) {
        HashMap map = new HashMap();
        try {
            JSONObject jSONObject = new JSONObject(str);
            Iterator<String> itKeys = jSONObject.keys();
            while (itKeys.hasNext()) {
                String next = itKeys.next();
                HashSet hashSet = new HashSet();
                JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray(next);
                if (jSONArrayOptJSONArray != null) {
                    for (int i = 0; i < jSONArrayOptJSONArray.length(); i++) {
                        String strOptString = jSONArrayOptJSONArray.optString(i);
                        if (strOptString != null) {
                            hashSet.add(strOptString);
                        }
                    }
                    map.put(next, hashSet);
                }
            }
            return map;
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.j.C.h.h("AdUtil.getMapOfFileNamesToKeysFromJsonString", e);
            return map;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v0, types: [android.view.View] */
    /* JADX WARN: Type inference failed for: r3v1 */
    /* JADX WARN: Type inference failed for: r3v6, types: [android.view.ViewParent] */
    public static final long K(View view) {
        float f;
        float fMin = Float.MAX_VALUE;
        do {
            boolean z = view instanceof View;
            f = DefinitionKt.NO_Float_VALUE;
            if (!z) {
                break;
            }
            View view2 = (View) view;
            fMin = Math.min(fMin, view2.getAlpha());
            view = view2.getParent();
        } while (fMin > DefinitionKt.NO_Float_VALUE);
        if (fMin >= DefinitionKt.NO_Float_VALUE) {
            f = fMin;
        }
        return Math.round(f * 100.0f);
    }

    public static final s a(Context context) throws IllegalAccessException, InstantiationException, IllegalArgumentException, InvocationTargetException {
        try {
            Object objNewInstance = context.getClassLoader().loadClass("com.google.android.gms.ads.internal.util.WorkManagerUtil").getDeclaredConstructor(null).newInstance(null);
            if (!(objNewInstance instanceof IBinder)) {
                com.google.android.gms.ads.internal.util.client.i.e("Instantiated WorkManagerUtil not instance of IBinder.");
                return null;
            }
            IBinder iBinder = (IBinder) objNewInstance;
            if (iBinder == null) {
                return null;
            }
            IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.util.IWorkManagerUtil");
            return iInterfaceQueryLocalInterface instanceof s ? (s) iInterfaceQueryLocalInterface : new r(iBinder, "com.google.android.gms.ads.internal.util.IWorkManagerUtil", 0);
        } catch (Exception e) {
            com.google.android.gms.ads.internal.j.C.h.h("Failed to instantiate WorkManagerUtil", e);
            return null;
        }
    }

    public static final boolean b(Context context, String str) {
        int i = AbstractC2009ec.a;
        Context applicationContext = context.getApplicationContext();
        if (applicationContext != null) {
            context = applicationContext;
        }
        return com.google.android.gms.common.wrappers.c.a(context).a.getPackageManager().checkPermission(str, context.getPackageName()) == 0;
    }

    public static final boolean c(Context context) {
        try {
            if (com.google.android.gms.common.util.c.h == null) {
                com.google.android.gms.common.util.c.h = Boolean.valueOf(com.google.android.gms.common.util.c.j() && context.getPackageManager().hasSystemFeature("com.google.android.play.feature.HPE_EXPERIENCE"));
            }
            return com.google.android.gms.common.util.c.h.booleanValue();
        } catch (NoSuchMethodError unused) {
            return false;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0054  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0064 A[ORIG_RETURN, RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean d(java.lang.String r6) {
        /*
            boolean r0 = com.google.android.gms.ads.internal.util.client.f.c()
            r1 = 0
            if (r0 != 0) goto L8
            goto L69
        L8:
            com.google.android.gms.internal.ads.s7 r0 = com.google.android.gms.internal.ads.AbstractC2773w7.g5
            com.google.android.gms.ads.internal.client.r r2 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r3 = r2.c
            java.lang.Object r0 = r3.a(r0)
            java.lang.Boolean r0 = (java.lang.Boolean) r0
            boolean r0 = r0.booleanValue()
            if (r0 != 0) goto L1b
            goto L69
        L1b:
            com.google.android.gms.internal.ads.s7 r0 = com.google.android.gms.internal.ads.AbstractC2773w7.i5
            com.google.android.gms.internal.ads.u7 r2 = r2.c
            java.lang.Object r0 = r2.a(r0)
            java.lang.String r0 = (java.lang.String) r0
            boolean r2 = r0.isEmpty()
            java.lang.String r3 = ";"
            if (r2 != 0) goto L41
            java.lang.String[] r0 = r0.split(r3)
            int r2 = r0.length
            r4 = r1
        L33:
            if (r4 >= r2) goto L41
            r5 = r0[r4]
            boolean r5 = r5.equals(r6)
            if (r5 == 0) goto L3e
            goto L69
        L3e:
            int r4 = r4 + 1
            goto L33
        L41:
            com.google.android.gms.internal.ads.s7 r0 = com.google.android.gms.internal.ads.AbstractC2773w7.h5
            com.google.android.gms.ads.internal.client.r r2 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r2 = r2.c
            java.lang.Object r0 = r2.a(r0)
            java.lang.String r0 = (java.lang.String) r0
            boolean r2 = r0.isEmpty()
            if (r2 == 0) goto L54
            goto L64
        L54:
            java.lang.String[] r0 = r0.split(r3)
            int r2 = r0.length
            r3 = r1
        L5a:
            if (r3 >= r2) goto L69
            r4 = r0[r3]
            boolean r4 = r4.equals(r6)
            if (r4 == 0) goto L66
        L64:
            r6 = 1
            return r6
        L66:
            int r3 = r3 + 1
            goto L5a
        L69:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.internal.util.F.d(java.lang.String):boolean");
    }

    public static final boolean e(Context context) {
        try {
            context.getClassLoader().loadClass("com.google.android.gms.ads.internal.ClientApi");
            return false;
        } catch (ClassNotFoundException unused) {
            return true;
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.i.f("Error loading class.", th);
            com.google.android.gms.ads.internal.j.C.h.h("AdUtil.isLiteSdk", th);
            return false;
        }
    }

    public static final boolean f(Context context) {
        List<ActivityManager.RunningAppProcessInfo> runningAppProcesses;
        PowerManager powerManager;
        try {
            ActivityManager activityManager = (ActivityManager) context.getSystemService("activity");
            KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService("keyguard");
            if (activityManager == null || keyguardManager == null || (runningAppProcesses = activityManager.getRunningAppProcesses()) == null) {
                return false;
            }
            for (ActivityManager.RunningAppProcessInfo runningAppProcessInfo : runningAppProcesses) {
                if (Process.myPid() == runningAppProcessInfo.pid) {
                    if (runningAppProcessInfo.importance == 100 && !keyguardManager.inKeyguardRestrictedInputMode() && (powerManager = (PowerManager) context.getSystemService("power")) != null) {
                        return !powerManager.isScreenOn();
                    }
                    return true;
                }
            }
            return true;
        } catch (Throwable unused) {
        }
        return false;
    }

    public static final boolean g(Context context) {
        try {
            Bundle bundleU = u(context);
            String string = bundleU.getString("com.google.android.gms.ads.INTEGRATION_MANAGER");
            if (TextUtils.isEmpty(v(bundleU))) {
                if (!TextUtils.isEmpty(string)) {
                    return true;
                }
            }
        } catch (RemoteException unused) {
        }
        return false;
    }

    public static final boolean h(Context context) {
        Window window;
        if ((context instanceof Activity) && (window = ((Activity) context).getWindow()) != null && window.getDecorView() != null) {
            Rect rect = new Rect();
            Rect rect2 = new Rect();
            window.getDecorView().getGlobalVisibleRect(rect, null);
            window.getDecorView().getWindowVisibleDisplayFrame(rect2);
            if (rect.bottom != 0 && rect2.bottom != 0 && rect.top == rect2.top) {
                return true;
            }
        }
        return false;
    }

    public static final void i(int i, View view) {
        String strA;
        int i2;
        int iHeight;
        int iWidth;
        String str;
        Vp vpE;
        Xp xpI0;
        View childAt = view;
        int[] iArr = new int[2];
        Rect rect = new Rect();
        try {
            String packageName = childAt.getContext().getPackageName();
            if (childAt instanceof C2492pk) {
                childAt = ((C2492pk) childAt).getChildAt(0);
            }
            if (childAt instanceof NativeAdView) {
                strA = "NATIVE";
                i2 = 1;
            } else {
                strA = "UNKNOWN";
                i2 = 0;
            }
            if (childAt.getLocalVisibleRect(rect)) {
                iWidth = rect.width();
                iHeight = rect.height();
            } else {
                iHeight = 0;
                iWidth = 0;
            }
            F f = com.google.android.gms.ads.internal.j.C.c;
            long jK = K(childAt);
            childAt.getLocationOnScreen(iArr);
            int i3 = iArr[0];
            int i4 = iArr[1];
            boolean z = childAt instanceof InterfaceC2529qe;
            String str2 = IdHelperAndroid.NO_ID_AVAILABLE;
            if (!z || (xpI0 = ((InterfaceC2529qe) childAt).i0()) == null) {
                str = IdHelperAndroid.NO_ID_AVAILABLE;
            } else {
                str = xpI0.b;
                childAt.setContentDescription(str + ":" + childAt.hashCode());
            }
            if ((childAt instanceof InterfaceC2529qe) && (vpE = ((InterfaceC2529qe) childAt).e()) != null) {
                strA = Vp.a(vpE.b);
                i2 = vpE.e;
                str2 = vpE.E;
            }
            Locale locale = Locale.US;
            com.google.android.gms.ads.internal.util.client.i.g("<Ad hashCode=" + childAt.hashCode() + ", package=" + packageName + ", adNetCls=" + str2 + ", gwsQueryId=" + str + ", format=" + strA + ", impType=" + i2 + ", class=" + childAt.getClass().getName() + ", x=" + i3 + ", y=" + i4 + ", width=" + childAt.getWidth() + ", height=" + childAt.getHeight() + ", vWidth=" + iWidth + ", vHeight=" + iHeight + ", alpha=" + jK + ", state=" + Integer.toString(i, 2) + SimpleComparison.GREATER_THAN_OPERATION);
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.i.f("Failure getting view location.", e);
        }
    }

    public static final AlertDialog.Builder j(Context context) {
        G g = com.google.android.gms.ads.internal.j.C.f;
        return new AlertDialog.Builder(context, R.style.Theme.Material.Dialog.Alert);
    }

    public static final boolean k(Vp vp) {
        return ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.ld)).booleanValue() && vp != null && vp.e == 4;
    }

    public static final int l(String str) {
        try {
            return Integer.parseInt(str);
        } catch (NumberFormatException e) {
            com.google.android.gms.ads.internal.util.client.i.h("Could not parse value:".concat(e.toString()));
            return 0;
        }
    }

    public static final HashMap m(Uri uri) {
        String encodedQuery;
        if (uri == null) {
            return null;
        }
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.q)).booleanValue()) {
            HashMap map = new HashMap();
            for (String str : uri.getQueryParameterNames()) {
                if (!TextUtils.isEmpty(str)) {
                    map.put(str, uri.getQueryParameter(str));
                }
            }
            return map;
        }
        HashMap map2 = new HashMap();
        if (!uri.isOpaque() && (encodedQuery = uri.getEncodedQuery()) != null) {
            int i = 0;
            while (true) {
                int iIndexOf = encodedQuery.indexOf(38, i);
                int length = encodedQuery.length();
                if (iIndexOf != -1) {
                    length = iIndexOf;
                }
                int iIndexOf2 = encodedQuery.indexOf(61, i);
                if (iIndexOf2 > length || iIndexOf2 == -1) {
                    iIndexOf2 = length;
                }
                map2.put(Uri.decode(encodedQuery.substring(i, iIndexOf2)), iIndexOf2 == length ? "" : Uri.decode(encodedQuery.substring(iIndexOf2 + 1, length)));
                if (iIndexOf == -1) {
                    break;
                }
                i = iIndexOf + 1;
            }
        }
        return map2;
    }

    public static final int[] n(Activity activity) {
        View viewFindViewById;
        Window window = activity.getWindow();
        return (window == null || (viewFindViewById = window.findViewById(R.id.content)) == null) ? new int[]{0, 0} : new int[]{viewFindViewById.getWidth(), viewFindViewById.getHeight()};
    }

    public static final int[] o(Activity activity) {
        View viewFindViewById;
        Window window = activity.getWindow();
        int[] iArr = (window == null || (viewFindViewById = window.findViewById(R.id.content)) == null) ? new int[]{0, 0} : new int[]{viewFindViewById.getTop(), viewFindViewById.getBottom()};
        C1614q c1614q = C1614q.f;
        return new int[]{c1614q.a.f(activity, iArr[0]), c1614q.a.f(activity, iArr[1])};
    }

    public static final boolean p(View view, PowerManager powerManager, KeyguardManager keyguardManager) {
        boolean z = com.google.android.gms.ads.internal.j.C.c.e || keyguardManager == null || !keyguardManager.inKeyguardRestrictedInputMode() || E(view);
        long jK = K(view);
        if (view.getVisibility() == 0 && view.isShown() && ((powerManager == null || powerManager.isScreenOn()) && z)) {
            C2601s7 c2601s7 = AbstractC2773w7.p1;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            if (!((Boolean) rVar.c.a(c2601s7)).booleanValue() || view.getLocalVisibleRect(new Rect()) || view.getGlobalVisibleRect(new Rect())) {
                C2601s7 c2601s72 = AbstractC2773w7.Ca;
                if (!((Boolean) rVar.c.a(c2601s72)).booleanValue() || jK >= ((Integer) r6.a(AbstractC2773w7.Ea)).intValue()) {
                    return true;
                }
            }
        }
        return false;
    }

    public static final void q(Context context, Intent intent) {
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Za)).booleanValue()) {
            try {
                context.startActivity(intent);
                return;
            } catch (Throwable unused) {
                intent.addFlags(268435456);
                context.startActivity(intent);
                return;
            }
        }
        try {
            try {
                context.startActivity(intent);
            } catch (Throwable unused2) {
                intent.addFlags(268435456);
                context.startActivity(intent);
            }
        } catch (SecurityException e) {
            com.google.android.gms.ads.internal.util.client.i.i("", e);
            com.google.android.gms.ads.internal.j.C.h.h("AdUtil.startActivityWithUnknownContext", e);
        }
    }

    public static final void r(Context context, Uri uri) {
        try {
            Intent intent = new Intent("android.intent.action.VIEW", uri);
            Bundle bundle = new Bundle();
            intent.putExtras(bundle);
            F(context, intent);
            bundle.putString("com.android.browser.application_id", context.getPackageName());
            context.startActivity(intent);
            com.google.android.gms.ads.internal.util.client.i.d("Opening " + uri.toString() + " in a new browser.");
        } catch (ActivityNotFoundException e) {
            com.google.android.gms.ads.internal.util.client.i.f("No browser is found.", e);
        }
    }

    public static final void s(Context context, Intent intent, Hk hk, String str) {
        C2601s7 c2601s7 = AbstractC2773w7.Zc;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u72 = rVar.c;
        if (!((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s7)).booleanValue() || !(context instanceof C1693Fe)) {
            q(context, intent);
            return;
        }
        try {
            Uri data = intent.getData();
            if (data == null || data.toString() == null || !data.toString().matches((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(AbstractC2773w7.bd))) {
                q(context, intent);
                return;
            }
            ((C1693Fe) context).a(intent);
            if (!((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(AbstractC2773w7.ad)).booleanValue() || hk == null) {
                return;
            }
            Fi fiA = hk.a();
            fiA.o("action", "hila");
            if (str == null) {
                str = "";
            }
            fiA.o("gqi", str);
            ((Hk) fiA.c).b.execute(new Fk(fiA, 2));
        } catch (ActivityNotFoundException e) {
            e = e;
            com.google.android.gms.ads.internal.util.client.i.f("Error occurred while starting activity for result", e);
            com.google.android.gms.ads.internal.j.C.h.h("AdUtil.startActivityForResult", e);
            q(context, intent);
        } catch (SecurityException e2) {
            e = e2;
            com.google.android.gms.ads.internal.util.client.i.f("Error occurred while starting activity for result", e);
            com.google.android.gms.ads.internal.j.C.h.h("AdUtil.startActivityForResult", e);
            q(context, intent);
        } catch (Exception e3) {
            com.google.android.gms.ads.internal.util.client.i.f("Error occurred while starting activity for result", e3);
            com.google.android.gms.ads.internal.j.C.h.h("AdUtil.startActivityForResult", e3);
            q(context, intent);
        }
    }

    public static int t(int i) {
        if (i >= 5000) {
            return i;
        }
        if (i <= 0) {
            return 60000;
        }
        com.google.android.gms.ads.internal.util.client.i.h("HTTP timeout too low: " + i + " milliseconds. Reverting to default timeout: 60000 milliseconds.");
        return 60000;
    }

    public static Bundle u(Context context) {
        try {
            return com.google.android.gms.common.wrappers.c.a(context).a(context.getPackageName(), 128).metaData;
        } catch (PackageManager.NameNotFoundException | NullPointerException unused) {
            A.m();
            return null;
        }
    }

    public static String v(Bundle bundle) {
        if (bundle == null) {
            return "";
        }
        String string = bundle.getString("com.google.android.gms.ads.APPLICATION_ID");
        return !TextUtils.isEmpty(string) ? (string.matches("^ca-app-pub-[0-9]{16}~[0-9]{10}$") || string.matches("^/\\d+~.+$")) ? string : "" : "";
    }

    public static boolean w(String str, AtomicReference atomicReference, String str2) {
        if (TextUtils.isEmpty(str)) {
            return false;
        }
        try {
            Pattern patternCompile = (Pattern) atomicReference.get();
            if (patternCompile == null || !str2.equals(patternCompile.pattern())) {
                patternCompile = Pattern.compile(str2);
                atomicReference.set(patternCompile);
            }
            return patternCompile.matcher(str).matches();
        } catch (PatternSyntaxException unused) {
            return false;
        }
    }

    public static final String x(Context context, String str) {
        String strH;
        if (str == null) {
            return H();
        }
        try {
            if (androidx.emoji2.text.r.b == null) {
                androidx.emoji2.text.r.b = new androidx.emoji2.text.r();
            }
            androidx.emoji2.text.r rVar = androidx.emoji2.text.r.b;
            if (TextUtils.isEmpty(rVar.a)) {
                rVar.a = (String) X2.d(context, new y(0, com.google.android.gms.common.d.a(context), context));
            }
            strH = rVar.a;
        } catch (Exception unused) {
            strH = null;
        }
        if (TextUtils.isEmpty(strH)) {
            strH = WebSettings.getDefaultUserAgent(context);
        }
        if (TextUtils.isEmpty(strH)) {
            strH = H();
        }
        String strL = android.support.v4.media.session.a.l(strH, " (Mobile; ", str);
        try {
            if (com.google.android.gms.common.wrappers.c.a(context).d()) {
                strL = strL + ";aia";
            }
        } catch (Exception e) {
            com.google.android.gms.ads.internal.j.C.h.h("AdUtil.getUserAgent", e);
        }
        return strL.concat(")");
    }

    public static ArrayList z() {
        C2601s7 c2601s7 = AbstractC2773w7.a;
        ArrayList arrayListO = com.google.android.gms.ads.internal.client.r.d.a.o();
        ArrayList arrayList = new ArrayList();
        Iterator it2 = arrayListO.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            C2883yp c2883ypE = C2883yp.e(new C2501pt(','));
            str.getClass();
            Iterator itE = ((At) c2883ypE.b).e(c2883ypE, str);
            while (true) {
                AbstractC2930zt abstractC2930zt = (AbstractC2930zt) itE;
                if (abstractC2930zt.hasNext()) {
                    try {
                        arrayList.add(Long.valueOf((String) abstractC2930zt.next()));
                    } catch (NumberFormatException unused) {
                        A.l("Experiment ID is not a number");
                    }
                }
            }
        }
        return arrayList;
    }

    public final void A(Context context, String str, HttpURLConnection httpURLConnection, int i) {
        int iT = t(i);
        com.google.android.gms.ads.internal.util.client.i.g("HTTP timeout: " + iT + " milliseconds.");
        httpURLConnection.setConnectTimeout(iT);
        httpURLConnection.setInstanceFollowRedirects(false);
        httpURLConnection.setReadTimeout(iT);
        if (TextUtils.isEmpty(httpURLConnection.getRequestProperty("User-Agent"))) {
            httpURLConnection.setRequestProperty("User-Agent", y(context, str));
        }
        httpURLConnection.setUseCaches(false);
    }

    public final void B(Context context) {
        if (this.j) {
            return;
        }
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction("com.google.android.ads.intent.DEBUG_LOGGING_ENABLEMENT_CHANGED");
        AbstractC2773w7.a(context);
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ya)).booleanValue() || Build.VERSION.SDK_INT < 33) {
            context.getApplicationContext().registerReceiver(new E(0), intentFilter);
        } else {
            context.getApplicationContext().registerReceiver(new E(0), intentFilter, 4);
        }
        this.j = true;
    }

    public final void C(Context context) {
        if (this.i) {
            return;
        }
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction("android.intent.action.USER_PRESENT");
        intentFilter.addAction("android.intent.action.SCREEN_OFF");
        AbstractC2773w7.a(context);
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ya)).booleanValue() || Build.VERSION.SDK_INT < 33) {
            context.getApplicationContext().registerReceiver(new C1549d(this, 6), intentFilter);
        } else {
            context.getApplicationContext().registerReceiver(new C1549d(this, 6), intentFilter, 4);
        }
        this.i = true;
    }

    public final String y(Context context, String str) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.lb)).booleanValue()) {
            if (this.h != null) {
                return this.h;
            }
            this.h = x(context, str);
            return this.h;
        }
        synchronized (this.f) {
            try {
                String str2 = this.g;
                if (str2 != null) {
                    return str2;
                }
                String strX = x(context, str);
                this.g = strX;
                return strX;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
