package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class G2 {
    public static final void a(com.quizlet.features.settings.data.states.y settingsUiState, com.quizlet.features.settings.composables.j offlineStudyingActions, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.ui.q qVar2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(settingsUiState, "settingsUiState");
        Intrinsics.checkNotNullParameter(offlineStudyingActions, "offlineStudyingActions");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-2114884629);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(settingsUiState) : c0814p2.h(settingsUiState) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(offlineStudyingActions) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            qVar2 = qVar;
            i2 |= c0814p2.f(qVar2) ? 256 : 128;
        } else {
            qVar2 = qVar;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            com.google.android.gms.internal.mlkit_vision_document_scanner.R4.a(qVar2, null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(-1391932047, new com.quizlet.features.settings.composables.k(settingsUiState, offlineStudyingActions, 1), c0814p2), c0814p, (i2 >> 6) & 14, 1022);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 4, qVar, (Object) settingsUiState, (Object) offlineStudyingActions);
        }
    }

    public static final void b(com.quizlet.features.settings.data.states.y settingsUiState, com.quizlet.features.settings.composables.j offlineStudyingActions, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        Intrinsics.checkNotNullParameter(settingsUiState, "settingsUiState");
        Intrinsics.checkNotNullParameter(offlineStudyingActions, "offlineStudyingActions");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(773208466);
        int i2 = (c0814p.f(settingsUiState) ? 4 : 2) | i | (c0814p.f(offlineStudyingActions) ? 32 : 16) | 384;
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            M2.c(AbstractC3106b5.d(c0814p, R.string.offline_studying_section_title), null, c0814p, 0);
            com.quizlet.themes.m.g.u();
            a(settingsUiState, offlineStudyingActions, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, i2 & 126);
            c0814p.p(true);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 12, settingsUiState, offlineStudyingActions, qVar2);
        }
    }

    public static final void c(String str) {
        File fileD = d();
        if (fileD == null || str == null) {
            return;
        }
        new File(fileD, str).delete();
    }

    public static final File d() {
        File file = new File(com.facebook.o.a().getCacheDir(), "instrument");
        if (file.exists() || file.mkdirs()) {
            return file;
        }
        return null;
    }

    public static final boolean e(StackTraceElement element) {
        Intrinsics.checkNotNullParameter(element, "element");
        String className = element.getClassName();
        Intrinsics.checkNotNullExpressionValue(className, "element.className");
        if (kotlin.text.D.r(className, "com.facebook", false)) {
            return true;
        }
        String className2 = element.getClassName();
        Intrinsics.checkNotNullExpressionValue(className2, "element.className");
        return kotlin.text.D.r(className2, "com.meta", false);
    }

    public static final boolean f(Thread thread) {
        StackTraceElement[] stackTrace = thread.getStackTrace();
        if (stackTrace != null) {
            for (StackTraceElement element : stackTrace) {
                Intrinsics.checkNotNullExpressionValue(element, "element");
                if (e(element)) {
                    String className = element.getClassName();
                    Intrinsics.checkNotNullExpressionValue(className, "element.className");
                    if (!kotlin.text.D.r(className, "com.facebook.appevents.codeless", false)) {
                        String className2 = element.getClassName();
                        Intrinsics.checkNotNullExpressionValue(className2, "element.className");
                        if (!kotlin.text.D.r(className2, "com.facebook.appevents.suggestedevents", false)) {
                            return true;
                        }
                    }
                    String methodName = element.getMethodName();
                    Intrinsics.checkNotNullExpressionValue(methodName, "element.methodName");
                    if (kotlin.text.D.r(methodName, "onClick", false)) {
                        continue;
                    } else {
                        String methodName2 = element.getMethodName();
                        Intrinsics.checkNotNullExpressionValue(methodName2, "element.methodName");
                        if (kotlin.text.D.r(methodName2, "onItemClick", false)) {
                            continue;
                        } else {
                            String methodName3 = element.getMethodName();
                            Intrinsics.checkNotNullExpressionValue(methodName3, "element.methodName");
                            if (!kotlin.text.D.r(methodName3, "onTouch", false)) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    public static final JSONObject g(String str) {
        File fileD = d();
        if (fileD == null || str == null) {
            return null;
        }
        try {
            return new JSONObject(com.facebook.internal.J.L(new FileInputStream(new File(fileD, str))));
        } catch (Exception unused) {
            c(str);
            return null;
        }
    }

    public static final void h(String str, JSONArray reports, com.facebook.q qVar) {
        Intrinsics.checkNotNullParameter(reports, "reports");
        if (reports.length() == 0) {
            return;
        }
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put(str, reports.toString());
            JSONObject jSONObjectO = com.facebook.internal.J.o();
            if (jSONObjectO != null) {
                Iterator<String> itKeys = jSONObjectO.keys();
                while (itKeys.hasNext()) {
                    String next = itKeys.next();
                    jSONObject.put(next, jSONObjectO.get(next));
                }
            }
            String str2 = com.facebook.t.j;
            assistantMode.utils.studiableMetadata.b.R(null, androidx.compose.animation.d0.s(new Object[]{com.facebook.o.b()}, 1, "%s/instruments", "format(format, *args)"), jSONObject, qVar).d();
        } catch (JSONException unused) {
        }
    }

    public static final void i(String str, String str2) {
        File fileD = d();
        if (fileD == null || str == null || str2 == null) {
            return;
        }
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(new File(fileD, str));
            byte[] bytes = str2.getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            fileOutputStream.write(bytes);
            fileOutputStream.close();
        } catch (Exception unused) {
        }
    }
}
