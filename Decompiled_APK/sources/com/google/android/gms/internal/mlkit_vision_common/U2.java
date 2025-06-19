package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.AbstractC0809m0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2501pt;
import com.google.android.gms.internal.ads.C2883yp;
import com.google.android.gms.internal.ads.Rs;
import com.google.android.gms.internal.ads.Ss;
import com.google.android.gms.internal.ads.Ts;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4392k;
import com.quizlet.features.settings.viewmodels.C4444b;
import com.quizlet.features.settings.viewmodels.C4447e;
import com.quizlet.quizletandroid.R;
import java.io.IOException;
import java.util.List;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class U2 {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, com.quizlet.features.settings.viewmodels.l lVar, Function0 function0, Function0 function02) {
        com.quizlet.features.settings.viewmodels.l lVar2;
        int i2;
        com.quizlet.features.settings.viewmodels.l lVar3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-426112275);
        int i3 = i | 2 | (c0814p.h(function0) ? 32 : 16) | (c0814p.h(function02) ? 256 : 128);
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            lVar3 = lVar;
        } else {
            c0814p.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                Object objE = AbstractC3417z1.e(C4444b.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                lVar2 = (com.quizlet.features.settings.viewmodels.l) objE;
                i2 = i3 & (-15);
            } else {
                c0814p.Q();
                i2 = i3 & (-15);
                lVar2 = lVar;
            }
            c0814p.q();
            C4444b c4444b = (C4444b) lVar2;
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(c4444b.f, c0814p);
            com.quizlet.data.interactor.course.a aVar = new com.quizlet.data.interactor.course.a(new com.quizlet.features.settings.composables.x(1, lVar2, com.quizlet.features.settings.viewmodels.l.class, "onRequestUpdateEmail", "onRequestUpdateEmail(Ljava/lang/String;)V", 0, 5));
            kotlinx.coroutines.flow.d0 d0Var = ((C4447e) lVar2).b;
            c0814p.X(1382342192);
            boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            if (z || objI == v) {
                objI = new com.quizlet.features.settings.composables.changeuseremail.l(function0, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            AbstractC0809m0 abstractC0809m0 = androidx.lifecycle.compose.g.a;
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zH = c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(b) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                objI2 = new com.quizlet.features.settings.composables.changeuseremail.i(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI2);
            c0814p.p(false);
            kotlinx.coroutines.flow.d0 d0Var2 = c4444b.h;
            c0814p.X(1382345199);
            boolean z2 = (i2 & 896) == 256;
            Object objI3 = c0814p.I();
            if (z2 || objI3 == v) {
                objI3 = new com.quizlet.features.settings.composables.changeuseremail.m(function02, null);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j2 = (androidx.lifecycle.J) c0814p.j(abstractC0809m0);
            InterfaceC0773a0 interfaceC0773a0D2 = C0776c.D((Function2) objI3, c0814p);
            c0814p.X(1667431386);
            boolean zH2 = c0814p.h(j2) | c0814p.h(d0Var2) | c0814p.f(b) | c0814p.f(interfaceC0773a0D2);
            Object objI4 = c0814p.I();
            if (zH2 || objI4 == v) {
                objI4 = new com.quizlet.features.settings.composables.changeuseremail.k(interfaceC0773a0D2, j2, null, d0Var2);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            b((com.quizlet.features.settings.data.states.d) AbstractC4178x.k(unit, (Function2) objI4, c0814p, false, interfaceC0773a0M), aVar, function0, c0814p, (i2 << 3) & 896);
            lVar3 = lVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.changeuseremail.a(lVar3, function0, function02, i);
        }
    }

    public static final void b(com.quizlet.features.settings.data.states.d dVar, com.quizlet.data.interactor.course.a aVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        int i3 = 4;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1135028866);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(dVar) : c0814p2.h(dVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(aVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function0) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 != 0 && !c0814p2.w()) {
                c0814p2.Q();
            }
            c0814p2.q();
            Object[] objArr = new Object[0];
            c0814p2.X(1573493938);
            Object objI = c0814p2.I();
            if (objI == v) {
                objI = new C4392k(28);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI, c0814p2, 3072, 6);
            androidx.compose.ui.focus.h hVar = (androidx.compose.ui.focus.h) c0814p2.j(AbstractC0955m0.g);
            long jG = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g();
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(null, androidx.compose.runtime.internal.e.e(-1270513854, new com.quizlet.assembly.compose.buttons.A((Object) hVar, (Object) function0, (Object) aVar, interfaceC0773a0, 15), c0814p2), null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(764044237, new com.quizlet.features.questiontypes.mcq.ui.c(i3, dVar, interfaceC0773a0), c0814p2), c0814p, 805306416, 189);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 10, dVar, aVar, function0);
        }
    }

    public static final void c(Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        Function0 function03;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(480625184);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i | (c0814p.h(function02) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function03 = function0;
        } else {
            function03 = function0;
            N2.b(null, AbstractC3106b5.d(c0814p, R.string.update_email_title), 0L, null, function03, androidx.compose.runtime.internal.e.e(-1214621888, new com.quizlet.features.infra.folder.create.coursefolder.composable.k(5, function02), c0814p), c0814p, ((i2 << 12) & 57344) | 196608, 13);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.upload.composables.common.d(function03, function02, i, 2);
        }
    }

    public static Bundle d(Context context, String str) {
        JSONArray jSONArray;
        Object obj;
        SharedPreferences sharedPreferences;
        String str2;
        if (TextUtils.isEmpty(str)) {
            jSONArray = null;
        } else {
            try {
                jSONArray = new JSONArray(str);
            } catch (JSONException unused) {
                com.google.android.gms.ads.internal.util.client.i.k(3);
            }
        }
        if (jSONArray == null) {
            return Bundle.EMPTY;
        }
        Bundle bundle = new Bundle();
        for (int i = 0; i < jSONArray.length(); i++) {
            JSONObject jSONObjectOptJSONObject = jSONArray.optJSONObject(i);
            String strOptString = jSONObjectOptJSONObject.optString("bk");
            String strOptString2 = jSONObjectOptJSONObject.optString("sk");
            int iOptInt = jSONObjectOptJSONObject.optInt(DBUserFields.Names.USER_UPGRADE_TYPE, -1);
            int i2 = iOptInt != 0 ? iOptInt != 1 ? iOptInt != 2 ? 0 : 3 : 2 : 1;
            if (!TextUtils.isEmpty(strOptString) && !TextUtils.isEmpty(strOptString2) && i2 != 0) {
                List listK = C2883yp.e(new C2501pt('/')).k(strOptString2);
                if (listK.size() > 2 || listK.isEmpty()) {
                    obj = null;
                } else {
                    if (listK.size() == 1) {
                        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
                        str2 = (String) listK.get(0);
                    } else {
                        sharedPreferences = context.getSharedPreferences((String) listK.get(0), 0);
                        str2 = (String) listK.get(1);
                    }
                    obj = sharedPreferences.getAll().get(str2);
                }
                if (obj != null) {
                    int i3 = i2 - 1;
                    if (i3 != 0) {
                        if (i3 != 1) {
                            if (obj instanceof Boolean) {
                                bundle.putBoolean(strOptString, ((Boolean) obj).booleanValue());
                            }
                        } else if (obj instanceof Integer) {
                            bundle.putInt(strOptString, ((Integer) obj).intValue());
                        } else if (obj instanceof Long) {
                            bundle.putLong(strOptString, ((Long) obj).longValue());
                        } else if (obj instanceof Float) {
                            bundle.putFloat(strOptString, ((Float) obj).floatValue());
                        }
                    } else if (obj instanceof String) {
                        bundle.putString(strOptString, (String) obj);
                    }
                }
            }
        }
        return bundle;
    }

    public static void e(Context context) throws IOException {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.g6)).booleanValue() && context != null) {
            context.deleteDatabase("OfflineUpload.db");
        }
        try {
            Rs rsF = Rs.f(context);
            Ss ssG = Ss.g(context);
            Ts tsJ = Ts.j(context);
            rsF.getClass();
            synchronized (Rs.class) {
                rsF.d(false);
            }
            synchronized (Rs.class) {
                rsF.d(true);
            }
            ssG.h();
            tsJ.n();
        } catch (IOException e) {
            com.google.android.gms.ads.internal.j.C.h.h("clearStorageOnIdlessMode", e);
        }
        try {
            if (context.getSharedPreferences("query_info_shared_prefs", 0).edit().clear().commit()) {
            } else {
                throw new IOException("Failed to remove query_info_shared_prefs");
            }
        } catch (IOException e2) {
            com.google.android.gms.ads.internal.j.C.h.h("clearStorageOnIdlessMode_scar", e2);
        }
    }
}
