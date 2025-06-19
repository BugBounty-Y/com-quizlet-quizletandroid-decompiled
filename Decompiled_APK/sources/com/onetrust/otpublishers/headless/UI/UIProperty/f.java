package com.onetrust.otpublishers.headless.UI.UIProperty;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.c0;
import androidx.compose.runtime.internal.j;
import androidx.constraintlayout.motion.widget.n;
import androidx.navigation.internal.m;
import androidx.room.s;
import androidx.webkit.internal.p;
import com.google.android.gms.cloudmessaging.k;
import com.google.android.gms.internal.mlkit_common.u;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import java.util.Objects;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class f {
    public final c a;
    public final d b;
    public final a e;
    public final b f;
    public final com.google.android.material.shape.e d = new com.google.android.material.shape.e(22);
    public final u c = new u(22);

    public f(@NonNull Context context) {
        this.a = new c(context);
        this.b = new d(context);
        this.e = new a(context);
        this.f = new b(context);
    }

    /* JADX WARN: Removed duplicated region for block: B:108:0x024c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.profileinstaller.a a() {
        /*
            Method dump skipped, instructions count: 1040
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.f.a():androidx.profileinstaller.a");
    }

    /* JADX WARN: Removed duplicated region for block: B:116:0x026a  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x00db  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x011c  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0147  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0165  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0179  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x01a4  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x01d1  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x01f9  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.profileinstaller.a b(com.onetrust.otpublishers.headless.Internal.Helper.k r20, int r21) {
        /*
            Method dump skipped, instructions count: 706
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.f.b(com.onetrust.otpublishers.headless.Internal.Helper.k, int):androidx.profileinstaller.a");
    }

    public final e c(int i) throws JSONException {
        e eVar;
        c cVar = this.a;
        JSONObject jSONObjectB = cVar.b();
        JSONObject jSONObject = (jSONObjectB == null || !jSONObjectB.has(OTUXParamsKeys.OT_PREFERENCE_CENTER_THEME)) ? null : jSONObjectB.getJSONObject(OTUXParamsKeys.OT_PREFERENCE_CENTER_THEME);
        if (jSONObject != null) {
            eVar = new e();
            if (jSONObject.has(OTUXParamsKeys.OT_UX_BACKGROUND_COLOR)) {
                eVar.a = jSONObject.getString(OTUXParamsKeys.OT_UX_BACKGROUND_COLOR);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_LINE_BREAK_COLOR)) {
                eVar.b = jSONObject.getString(OTUXParamsKeys.OT_UX_LINE_BREAK_COLOR);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_TOGGLE_THUMB_COLOR_ON)) {
                eVar.c = jSONObject.getString(OTUXParamsKeys.OT_UX_TOGGLE_THUMB_COLOR_ON);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_TOGGLE_THUMB_COLOR_OFF)) {
                eVar.d = jSONObject.getString(OTUXParamsKeys.OT_UX_TOGGLE_THUMB_COLOR_OFF);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_TOGGLE_TRACK_COLOR)) {
                eVar.e = jSONObject.getString(OTUXParamsKeys.OT_UX_TOGGLE_TRACK_COLOR);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_RIGHT_CHEVRON_COLOR)) {
                eVar.g = jSONObject.getString(OTUXParamsKeys.OT_UX_RIGHT_CHEVRON_COLOR);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_SHOW_LOGO_ON_PC)) {
                com.google.android.gms.internal.appset.e eVar2 = new com.google.android.gms.internal.appset.e(10, false);
                eVar2.b = String.valueOf(jSONObject.getBoolean(OTUXParamsKeys.OT_UX_SHOW_LOGO_ON_PC));
                eVar.A = eVar2;
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_SUMMARY)) {
                JSONObject jSONObject2 = jSONObject.getJSONObject(OTUXParamsKeys.OT_UX_SUMMARY);
                if (jSONObject2.has("title")) {
                    JSONObject jSONObject3 = jSONObject2.getJSONObject("title");
                    eVar.k = c.g(jSONObject3);
                    eVar.s = c.g(jSONObject3);
                    eVar.v = c.g(jSONObject3);
                    eVar.m = c.g(jSONObject3);
                }
                if (jSONObject2.has(OTUXParamsKeys.OT_UX_DESCRIPTION)) {
                    JSONObject jSONObject4 = jSONObject2.getJSONObject(OTUXParamsKeys.OT_UX_DESCRIPTION);
                    eVar.l = c.g(jSONObject4);
                    eVar.r = c.g(jSONObject4);
                }
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_PURPOSE_TITLE)) {
                JSONObject jSONObject5 = jSONObject.getJSONObject(OTUXParamsKeys.OT_UX_PURPOSE_TITLE);
                eVar.t = c.g(jSONObject5);
                eVar.n = c.g(jSONObject5);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_TOGGLE_ALWAYS_ACTIVE_STATUS)) {
                eVar.u = c.g(jSONObject.getJSONObject(OTUXParamsKeys.OT_UX_TOGGLE_ALWAYS_ACTIVE_STATUS));
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_BUTTONS)) {
                JSONObject jSONObject6 = jSONObject.getJSONObject(OTUXParamsKeys.OT_UX_BUTTONS);
                if (jSONObject6.has(OTUXParamsKeys.OT_UX_CLOSE_BUTTON_COLOR)) {
                    String string = jSONObject6.getString(OTUXParamsKeys.OT_UX_CLOSE_BUTTON_COLOR);
                    c0 c0Var = new c0(13);
                    c0Var.f = string;
                    eVar.z = c0Var;
                }
                if (jSONObject6.has(OTUXParamsKeys.OT_UX_CLOSE_BUTTON)) {
                    JSONObject jSONObject7 = jSONObject6.getJSONObject(OTUXParamsKeys.OT_UX_CLOSE_BUTTON);
                    c0 c0Var2 = eVar.z;
                    n nVarA = c.a(jSONObject7);
                    if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVarA.e)) {
                        nVarA.k = "true";
                        c0Var2.g = nVarA;
                        eVar.z = c0Var2;
                    }
                }
                if (jSONObject6.has(OTUXParamsKeys.OT_UX_BACK_BUTTON_COLOR)) {
                    eVar.C = jSONObject6.getString(OTUXParamsKeys.OT_UX_BACK_BUTTON_COLOR);
                }
                if (jSONObject6.has(OTUXParamsKeys.OT_UX_ACCEPT_ALL)) {
                    eVar.w = c.a(jSONObject6.getJSONObject(OTUXParamsKeys.OT_UX_ACCEPT_ALL));
                }
                if (jSONObject6.has(OTUXParamsKeys.OT_UX_REJECT_ALL)) {
                    eVar.x = c.a(jSONObject6.getJSONObject(OTUXParamsKeys.OT_UX_REJECT_ALL));
                }
                if (jSONObject6.has(OTUXParamsKeys.OT_UX_CONFIRM_CHOICE)) {
                    eVar.y = c.a(jSONObject6.getJSONObject(OTUXParamsKeys.OT_UX_CONFIRM_CHOICE));
                }
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_LINKS)) {
                JSONObject jSONObject8 = jSONObject.getJSONObject(OTUXParamsKeys.OT_UX_LINKS);
                if (jSONObject8.has(OTUXParamsKeys.OT_UX_LINK_POLICY_LINK)) {
                    eVar.D = c.e(jSONObject8.getJSONObject(OTUXParamsKeys.OT_UX_LINK_POLICY_LINK));
                }
                if (jSONObject8.has(OTUXParamsKeys.OT_UX_LINK_VENDOR_LIST)) {
                    eVar.E = c.e(jSONObject8.getJSONObject(OTUXParamsKeys.OT_UX_LINK_VENDOR_LIST));
                }
            }
        } else {
            eVar = null;
        }
        e eVarF = this.b.f(i);
        s sVarC = cVar.c();
        this.d.getClass();
        if (eVar == null) {
            if (sVarC != null && !com.onetrust.otpublishers.headless.Internal.a.j(sVarC.b)) {
                String str = sVarC.b;
                if (eVarF == null) {
                    return null;
                }
                com.quizlet.data.repository.user.e eVar3 = eVarF.D;
                m mVar = (m) eVar3.b;
                mVar.b = str;
                eVar3.b = mVar;
                eVarF.D = eVar3;
            }
            return eVarF;
        }
        if (eVarF != null) {
            String strK = com.google.android.material.shape.e.k(eVar.a, eVarF.a);
            if (strK != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK)) {
                eVar.a = strK;
            }
            String strK2 = com.google.android.material.shape.e.k(eVar.h, eVarF.h);
            if (strK2 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK2)) {
                eVar.h = strK2;
            }
            String strK3 = com.google.android.material.shape.e.k(eVar.g, eVarF.g);
            if (strK3 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK3)) {
                eVar.g = strK3;
            }
            eVar.i = eVarF.i;
            m mVar2 = eVar.k;
            com.google.android.material.shape.e.o(mVar2, eVarF.k);
            eVar.k = mVar2;
            m mVar3 = eVar.m;
            com.google.android.material.shape.e.o(mVar3, eVarF.m);
            eVar.m = mVar3;
            m mVar4 = eVar.q;
            com.google.android.material.shape.e.o(mVar4, eVarF.q);
            eVar.q = mVar4;
            m mVar5 = eVar.o;
            com.google.android.material.shape.e.o(mVar5, eVarF.o);
            eVar.o = mVar5;
            m mVar6 = eVar.p;
            com.google.android.material.shape.e.o(mVar6, eVarF.p);
            eVar.p = mVar6;
            eVar.K = com.google.android.material.shape.e.k(eVar.K, eVarF.K);
            m mVar7 = eVar.l;
            com.google.android.material.shape.e.o(mVar7, eVarF.l);
            eVar.l = mVar7;
            m mVar8 = eVar.r;
            com.google.android.material.shape.e.o(mVar8, eVarF.r);
            eVar.r = mVar8;
            m mVar9 = eVar.s;
            com.google.android.material.shape.e.o(mVar9, eVarF.s);
            eVar.s = mVar9;
            m mVar10 = eVar.v;
            com.google.android.material.shape.e.o(mVar10, eVarF.v);
            eVar.v = mVar10;
            m mVar11 = eVar.n;
            com.google.android.material.shape.e.o(mVar11, eVarF.n);
            eVar.n = mVar11;
            eVar.I = com.google.android.material.shape.e.k(eVar.I, eVarF.I);
            eVar.J = com.google.android.material.shape.e.k(eVar.J, eVarF.J);
            com.quizlet.data.repository.user.e eVarI = com.google.android.material.shape.e.i(eVar.D, eVarF.D, sVarC);
            eVarI.d = (String) eVarF.D.d;
            eVar.D = eVarI;
            com.quizlet.data.repository.user.e eVar4 = eVar.E;
            com.google.android.material.shape.e.q(eVar4, eVarF.E);
            eVar.E = eVar4;
            com.quizlet.data.repository.user.e eVar5 = eVar.F;
            com.google.android.material.shape.e.q(eVar5, eVarF.F);
            m mVar12 = (m) eVarF.F.b;
            String str2 = (String) mVar12.g;
            if (str2 != null) {
                ((m) eVar5.b).g = str2;
            }
            ((m) eVar5.b).c = mVar12.c;
            eVar.F = eVar5;
            eVar.j = eVarF.j;
            n nVar = eVar.w;
            com.google.android.material.shape.e.n(nVar, eVarF.w);
            eVar.w = nVar;
            n nVar2 = eVar.x;
            com.google.android.material.shape.e.n(nVar2, eVarF.x);
            eVar.x = nVar2;
            n nVar3 = eVar.y;
            com.google.android.material.shape.e.n(nVar3, eVarF.y);
            eVar.y = nVar3;
            c0 c0Var3 = eVar.z;
            com.google.android.material.shape.e.l(c0Var3, eVarF.z);
            eVar.z = c0Var3;
            m mVar13 = eVar.u;
            m mVar14 = eVarF.u;
            String strK4 = com.google.android.material.shape.e.k((String) mVar13.b, (String) mVar14.b);
            if (strK4 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK4)) {
                mVar13.b = strK4;
            }
            k kVar = (k) mVar13.d;
            String strK5 = com.google.android.material.shape.e.k((String) kVar.d, (String) ((k) mVar14.d).d);
            if (strK5 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK5)) {
                kVar.d = strK5;
            }
            mVar13.d = kVar;
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) eVarF.u.g)) {
                mVar13.g = (String) eVarF.u.g;
            }
            eVar.u = mVar13;
            m mVar15 = eVar.t;
            m mVar16 = eVarF.t;
            String strK6 = com.google.android.material.shape.e.k((String) mVar15.b, (String) mVar16.b);
            if (strK6 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK6)) {
                mVar15.b = strK6;
            }
            k kVar2 = (k) mVar15.d;
            String strK7 = com.google.android.material.shape.e.k((String) kVar2.d, (String) ((k) mVar16.d).d);
            if (strK7 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK7)) {
                kVar2.d = strK7;
            }
            mVar15.d = kVar2;
            eVar.t = mVar15;
            com.google.android.gms.internal.appset.e eVar6 = eVar.A;
            com.google.android.gms.internal.appset.e eVar7 = eVarF.A;
            String strK8 = com.google.android.material.shape.e.k(eVar6.h(), eVar7.h());
            if (strK8 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK8)) {
                eVar6.c = strK8;
            }
            String strK9 = com.google.android.material.shape.e.k((String) eVar6.b, (String) eVar7.b);
            if (strK9 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK9)) {
                eVar6.b = strK9;
            }
            eVar.A = eVar6;
            String strK10 = com.google.android.material.shape.e.k(eVar.c, eVarF.c);
            if (strK10 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK10)) {
                eVar.c = strK10;
            }
            String strK11 = com.google.android.material.shape.e.k(eVar.d, eVarF.d);
            if (strK11 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK11)) {
                eVar.d = strK11;
            }
            String strK12 = com.google.android.material.shape.e.k(eVar.b, eVarF.b);
            if (strK12 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK12)) {
                eVar.b = strK12;
            }
        }
        return eVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x01ec  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x0248  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x0259  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x0262  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0177  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x0189  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0192  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0198  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.ads.Yh d(int r18) {
        /*
            Method dump skipped, instructions count: 905
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.f.d(int):com.google.android.gms.internal.ads.Yh");
    }

    /* JADX WARN: Removed duplicated region for block: B:110:0x0226  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x0234  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x015d  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x016e  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0177  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x017d  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x018e  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0197  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x019d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.ads.Zh e() throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 913
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.f.e():com.google.android.gms.internal.ads.Zh");
    }

    /* JADX WARN: Removed duplicated region for block: B:105:0x01e5  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x011b  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0136  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x013c  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0140  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0155  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x015b  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x015f  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x01a2  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x01c6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.ads.C3 f() throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 753
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.UIProperty.f.f():com.google.android.gms.internal.ads.C3");
    }

    public final g g(int i) {
        g gVar;
        c cVar = this.a;
        JSONObject jSONObjectB = cVar.b();
        p pVar = null;
        JSONObject jSONObject = (jSONObjectB == null || !jSONObjectB.has(OTUXParamsKeys.OT_VENDOR_LIST_THEME)) ? null : jSONObjectB.getJSONObject(OTUXParamsKeys.OT_VENDOR_LIST_THEME);
        if (jSONObject != null) {
            gVar = new g();
            if (jSONObject.has(OTUXParamsKeys.OT_UX_BACKGROUND_COLOR)) {
                gVar.a = jSONObject.getString(OTUXParamsKeys.OT_UX_BACKGROUND_COLOR);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_LINE_BREAK_COLOR)) {
                gVar.b = jSONObject.getString(OTUXParamsKeys.OT_UX_LINE_BREAK_COLOR);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_FILTER_COLOR_ON)) {
                gVar.f = jSONObject.getString(OTUXParamsKeys.OT_UX_FILTER_COLOR_ON);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_FILTER_COLOR_OFF)) {
                gVar.g = jSONObject.getString(OTUXParamsKeys.OT_UX_FILTER_COLOR_OFF);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_FILTER_SELECTION_COLOR)) {
                gVar.h = jSONObject.getString(OTUXParamsKeys.OT_UX_FILTER_SELECTION_COLOR);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_TOGGLE_THUMB_COLOR_ON)) {
                gVar.c = jSONObject.getString(OTUXParamsKeys.OT_UX_TOGGLE_THUMB_COLOR_ON);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_TOGGLE_THUMB_COLOR_OFF)) {
                gVar.d = jSONObject.getString(OTUXParamsKeys.OT_UX_TOGGLE_THUMB_COLOR_OFF);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_TOGGLE_TRACK_COLOR)) {
                gVar.e = jSONObject.getString(OTUXParamsKeys.OT_UX_TOGGLE_TRACK_COLOR);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_RIGHT_CHEVRON_COLOR)) {
                gVar.i = jSONObject.getString(OTUXParamsKeys.OT_UX_RIGHT_CHEVRON_COLOR);
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_SEARCH_BAR)) {
                gVar.n = c.f(jSONObject.getJSONObject(OTUXParamsKeys.OT_UX_SEARCH_BAR));
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_FILTER_NAVIGATION_TEXT)) {
                gVar.j = c.g(jSONObject.getJSONObject(OTUXParamsKeys.OT_UX_FILTER_NAVIGATION_TEXT));
            }
            if (jSONObject.has("title")) {
                gVar.k = c.g(jSONObject.getJSONObject("title"));
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_ALLOW_ALL_TOGGLE_TEXT)) {
                gVar.l = c.g(jSONObject.getJSONObject(OTUXParamsKeys.OT_UX_ALLOW_ALL_TOGGLE_TEXT));
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_FILTER_ITEM_TITLE_TEXT)) {
                gVar.m = c.g(jSONObject.getJSONObject(OTUXParamsKeys.OT_UX_FILTER_ITEM_TITLE_TEXT));
            }
            if (jSONObject.has(OTUXParamsKeys.OT_UX_BUTTONS)) {
                JSONObject jSONObject2 = jSONObject.getJSONObject(OTUXParamsKeys.OT_UX_BUTTONS);
                if (jSONObject2.has(OTUXParamsKeys.OT_UX_BACK_BUTTON_COLOR)) {
                    gVar.q = jSONObject2.getString(OTUXParamsKeys.OT_UX_BACK_BUTTON_COLOR);
                }
                if (jSONObject2.has(OTUXParamsKeys.OT_UX_VL_CONFIRM_CHOICE)) {
                    gVar.o = c.a(jSONObject2.getJSONObject(OTUXParamsKeys.OT_UX_VL_CONFIRM_CHOICE));
                }
                if (jSONObject2.has(OTUXParamsKeys.OT_UX_APPLY_FILTER_BUTTON)) {
                    gVar.p = c.a(jSONObject2.getJSONObject(OTUXParamsKeys.OT_UX_APPLY_FILTER_BUTTON));
                }
            }
        } else {
            gVar = null;
        }
        JSONObject jSONObjectB2 = cVar.b();
        JSONObject jSONObject3 = (jSONObjectB2 == null || !jSONObjectB2.has("pageHeader")) ? null : jSONObjectB2.getJSONObject("pageHeader");
        if (jSONObject3 != null) {
            pVar = new p(27);
            m mVar = new m();
            mVar.d = c.d(jSONObject3);
            if (jSONObject3.has(OTUXParamsKeys.OT_UX_TEXT_COLOR)) {
                mVar.b = jSONObject3.getString(OTUXParamsKeys.OT_UX_TEXT_COLOR);
            }
            pVar.b = mVar;
        }
        if (pVar != null) {
            (gVar == null ? new g() : gVar).r = pVar;
        }
        g gVarK = this.b.k(i);
        this.d.getClass();
        if (gVar == null) {
            return gVarK;
        }
        if (gVarK != null) {
            String strK = com.google.android.material.shape.e.k(gVar.q, gVarK.q);
            if (strK != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK)) {
                gVar.q = strK;
            }
            String strK2 = com.google.android.material.shape.e.k(gVar.a, gVarK.a);
            if (strK2 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK2)) {
                gVar.a = strK2;
            }
            String strK3 = com.google.android.material.shape.e.k(gVar.i, gVarK.i);
            if (strK3 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK3)) {
                gVar.i = strK3;
            }
            m mVar2 = gVar.k;
            com.google.android.material.shape.e.o(mVar2, gVarK.k);
            gVar.k = mVar2;
            m mVar3 = gVar.j;
            com.google.android.material.shape.e.o(mVar3, gVarK.j);
            gVar.j = mVar3;
            m mVar4 = gVar.m;
            m mVar5 = gVarK.m;
            String strK4 = com.google.android.material.shape.e.k((String) mVar4.b, (String) mVar5.b);
            if (strK4 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK4)) {
                mVar4.b = strK4;
            }
            k kVar = (k) mVar4.d;
            String strK5 = com.google.android.material.shape.e.k((String) kVar.d, (String) ((k) mVar5.d).d);
            if (strK5 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK5)) {
                kVar.d = strK5;
            }
            mVar4.d = kVar;
            gVar.m = mVar4;
            String strK6 = com.google.android.material.shape.e.k(gVar.h, gVarK.h);
            Objects.requireNonNull(strK6);
            gVar.h = strK6;
            j jVar = gVar.n;
            com.google.android.material.shape.e.m(jVar, gVarK.n);
            gVar.n = jVar;
            n nVar = gVar.o;
            com.google.android.material.shape.e.n(nVar, gVarK.o);
            gVar.o = nVar;
            n nVar2 = gVar.p;
            com.google.android.material.shape.e.n(nVar2, gVarK.p);
            gVar.p = nVar2;
            String strK7 = com.google.android.material.shape.e.k(gVar.f, gVarK.f);
            Objects.requireNonNull(strK7);
            gVar.f = strK7;
            String strK8 = com.google.android.material.shape.e.k(gVar.g, gVarK.g);
            Objects.requireNonNull(strK8);
            gVar.g = strK8;
            m mVar6 = gVar.l;
            com.google.android.material.shape.e.o(mVar6, gVarK.l);
            gVar.l = mVar6;
            String strK9 = com.google.android.material.shape.e.k(gVar.c, gVarK.c);
            if (strK9 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK9)) {
                gVar.c = strK9;
            }
            String strK10 = com.google.android.material.shape.e.k(gVar.d, gVarK.d);
            if (strK10 != null && !com.onetrust.otpublishers.headless.Internal.a.j(strK10)) {
                gVar.d = strK10;
            }
        }
        return gVar;
    }

    public f(Context context, int i) {
        this.a = new c(context);
        this.b = new d(context, i);
    }
}
