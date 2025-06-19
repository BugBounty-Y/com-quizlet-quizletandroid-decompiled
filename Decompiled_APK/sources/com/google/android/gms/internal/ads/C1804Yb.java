package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Resources;
import android.graphics.Insets;
import android.os.Build;
import android.util.DisplayMetrics;
import android.view.WindowInsets;
import android.view.WindowManager;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Yb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C1804Yb implements InterfaceC2544qt {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C1804Yb(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
    public final Object apply(Object obj) {
        boolean z;
        String str;
        float f;
        float f2;
        boolean z2;
        String strO;
        Insets insets;
        int i;
        int i2;
        float f3;
        Insets insetsOf;
        int i3;
        DisplayMetrics displayMetrics;
        int i4 = 0;
        int i5 = -1;
        String str2 = null;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                int i6 = 1;
                JSONObject jSONObject = (JSONObject) obj;
                C2601s7 c2601s7 = AbstractC2773w7.a;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                C1 c1 = rVar.b;
                com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = (com.quizlet.data.repository.studysetwithcreatorinclass.g) obj2;
                SharedPreferences sharedPreferencesL = C1.l((Context) gVar.c);
                if (sharedPreferencesL != null) {
                    SharedPreferences.Editor editorEdit = sharedPreferencesL.edit();
                    Iterator it2 = ((ArrayList) rVar.a.b).iterator();
                    while (it2.hasNext()) {
                        C2601s7 c2601s72 = (C2601s7) it2.next();
                        int i7 = i6;
                        if (c2601s72.a == i7) {
                            Object objA = c2601s72.a(jSONObject);
                            switch (c2601s72.e) {
                                case 0:
                                    editorEdit.putBoolean(c2601s72.b, ((Boolean) objA).booleanValue());
                                    break;
                                case 1:
                                    editorEdit.putInt(c2601s72.b, ((Integer) objA).intValue());
                                    break;
                                case 2:
                                    editorEdit.putLong(c2601s72.b, ((Long) objA).longValue());
                                    break;
                                case 3:
                                    editorEdit.putFloat(c2601s72.b, ((Float) objA).floatValue());
                                    break;
                                default:
                                    editorEdit.putString(c2601s72.b, (String) objA);
                                    break;
                            }
                        }
                        i6 = i7;
                    }
                    if (jSONObject != null) {
                        editorEdit.putString("flag_configuration", jSONObject.toString());
                    } else {
                        com.google.android.gms.ads.internal.util.client.i.e("Flag Json is null.");
                    }
                    C1 c12 = com.google.android.gms.ads.internal.client.r.d.b;
                    editorEdit.commit();
                    SharedPreferences sharedPreferences = (SharedPreferences) gVar.d;
                    if (sharedPreferences != null) {
                        SharedPreferences.Editor editorEdit2 = sharedPreferences.edit();
                        com.google.android.gms.ads.internal.j.C.k.getClass();
                        editorEdit2.putLong("js_last_update", System.currentTimeMillis()).apply();
                    }
                }
                return null;
            case 1:
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
                C1843ak c1843ak = (C1843ak) obj2;
                interfaceC2529qe.O0("/result", c1843ak.h);
                C1669Be c1669BeL = interfaceC2529qe.L();
                com.google.android.gms.ads.internal.a aVar = new com.google.android.gms.ads.internal.a(c1843ak.c, null);
                Wj wj = c1843ak.a;
                c1669BeL.q(null, wj, wj, wj, wj, false, null, aVar, null, null, c1843ak.i, c1843ak.j, c1843ak.d, null, null, null, null, null, null);
                return interfaceC2529qe;
            case 2:
                return ((C1783Ue) obj2).O();
            case 3:
                Wn wn = (Wn) obj2;
                C2023eq c2023eq = (C2023eq) wn.b;
                com.google.android.gms.ads.internal.client.zzr zzrVar = c2023eq.e;
                com.google.android.gms.ads.internal.client.zzr[] zzrVarArr = zzrVar.g;
                if (zzrVarArr == null) {
                    str = zzrVar.a;
                    z = zzrVar.i;
                } else {
                    z = false;
                    boolean z3 = false;
                    boolean z4 = false;
                    str = null;
                    for (com.google.android.gms.ads.internal.client.zzr zzrVar2 : zzrVarArr) {
                        boolean z5 = zzrVar2.i;
                        if (!z5 && !z3) {
                            str = zzrVar2.a;
                            z3 = true;
                        }
                        if (z5) {
                            if (z4) {
                                z4 = true;
                            } else {
                                z = true;
                                z4 = true;
                            }
                        }
                        if (!z3 || !z4) {
                        }
                    }
                }
                Context context = (Context) wn.c;
                Resources resources = context.getResources();
                int i8 = Build.VERSION.SDK_INT;
                Insets insets2 = i8 >= 29 ? Insets.NONE : null;
                if (resources == null || (displayMetrics = resources.getDisplayMetrics()) == null) {
                    f = DefinitionKt.NO_Float_VALUE;
                    f2 = 0.0f;
                    z2 = true;
                    strO = null;
                    insets = insets2;
                    i = 0;
                    i2 = 0;
                } else {
                    float f4 = displayMetrics.density;
                    f = DefinitionKt.NO_Float_VALUE;
                    int i9 = displayMetrics.widthPixels;
                    int i10 = displayMetrics.heightPixels;
                    f2 = f4;
                    i = i9;
                    strO = ((C2010ed) wn.e).d().o();
                    insets = insets2;
                    i2 = i10;
                    z2 = true;
                }
                if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.jd)).booleanValue() || i8 < 35) {
                    f3 = f2;
                    insetsOf = insets;
                } else {
                    WindowManager windowManager = (WindowManager) context.getSystemService("window");
                    if (windowManager == null || f2 == f) {
                        f3 = f2;
                        insetsOf = Insets.NONE;
                    } else {
                        Insets insets3 = windowManager.getCurrentWindowMetrics().getWindowInsets().getInsets(WindowInsets.Type.statusBars() | WindowInsets.Type.displayCutout() | WindowInsets.Type.navigationBars() | WindowInsets.Type.captionBar());
                        f3 = f2;
                        insetsOf = Insets.of((int) Math.ceil(insets3.left / f2), (int) Math.ceil(insets3.top / f2), (int) Math.ceil(insets3.right / f3), (int) Math.ceil(insets3.bottom / f3));
                    }
                }
                StringBuilder sb = new StringBuilder();
                if (zzrVarArr != null) {
                    boolean z6 = false;
                    for (com.google.android.gms.ads.internal.client.zzr zzrVar3 : zzrVarArr) {
                        if (zzrVar3.i) {
                            z6 = z2;
                        } else {
                            if (sb.length() != 0) {
                                sb.append("|");
                            }
                            int i11 = zzrVar3.e;
                            if (i11 == -1) {
                                i11 = f3 != f ? (int) (zzrVar3.f / f3) : -1;
                            }
                            sb.append(i11);
                            sb.append("x");
                            int i12 = -2;
                            int i13 = zzrVar3.b;
                            if (i13 != -2) {
                                i12 = i13;
                            } else if (f3 != f) {
                                i12 = (int) (zzrVar3.c / f3);
                            }
                            sb.append(i12);
                        }
                    }
                    if (z6) {
                        if (sb.length() != 0) {
                            i3 = 0;
                            sb.insert(0, "|");
                        } else {
                            i3 = 0;
                        }
                        sb.insert(i3, "320x50");
                    }
                }
                return new C2065fo(zzrVar, str, z, sb.toString(), f3, i, i2, strO, c2023eq.q, insetsOf);
            case 4:
                ((C2410no) obj2).a.h("AppSetIdInfoSignal", (Exception) obj);
                return new C2453oo(str2, i5, i4);
            case 5:
                ((C2010ed) ((C2021eo) obj2).b).h("AppSetIdInfoGmscoreSignal", (Exception) obj);
                return new C2453oo(str2, i5, 3);
            case 6:
                ((C2282kp) obj2).a.h("TrustlessTokenSignal", (Exception) obj);
                return new C1934co(str2, 5);
            default:
                C2755vq c2755vq = (C2755vq) obj2;
                c2755vq.c = (AbstractC2359mg) obj;
                return c2755vq;
        }
    }
}
