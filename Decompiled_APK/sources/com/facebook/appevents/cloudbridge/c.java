package com.facebook.appevents.cloudbridge;

import android.content.SharedPreferences;
import android.view.View;
import androidx.appcompat.app.Q;
import androidx.camera.core.C0195s;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.X;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import com.facebook.internal.A;
import com.facebook.o;
import com.facebook.y;
import com.quizlet.features.achievements.ui.composables.m;
import com.quizlet.themes.w;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class c {
    public static boolean a;

    public static final void a(String subTitle, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(subTitle, "subTitle");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1818577976);
        int i2 = i | (c0814p2.f(subTitle) ? 4 : 2);
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            K kE = AbstractC0409s.e(androidx.compose.ui.b.e, false);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            q qVarC = androidx.compose.ui.a.c(c0814p2, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0776c.E(c0814p2, kE, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            Q4.b(subTitle, null, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(w.b)).k, c0814p2, i2 & 14, 0, 65534);
            c0814p = c0814p2;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new m(subTitle, qVar, i, 0);
        }
    }

    public static C0195s b() {
        androidx.camera.camera2.a aVar = new androidx.camera.camera2.a();
        androidx.camera.camera2.b bVar = new androidx.camera.camera2.b();
        androidx.camera.camera2.c cVar = new androidx.camera.camera2.c();
        Q q = new Q(3);
        C0162c c0162c = C0195s.b;
        X x = (X) q.a;
        x.m(c0162c, aVar);
        x.m(C0195s.c, bVar);
        x.m(C0195s.d, cVar);
        return new C0195s(C0163c0.a(x));
    }

    public static final void c(View view, boolean z) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setVisibility(z ? 8 : 0);
    }

    public static void d(HashMap map) {
        SharedPreferences sharedPreferences = o.a().getSharedPreferences("com.facebook.sdk.CloudBridgeSavedCredentials", 0);
        if (sharedPreferences == null) {
            return;
        }
        Object obj = map.get("dataset_id");
        Object obj2 = map.get("endpoint");
        Object obj3 = map.get("access_key");
        if (obj == null || obj2 == null || obj3 == null) {
            return;
        }
        SharedPreferences.Editor editorEdit = sharedPreferences.edit();
        editorEdit.putString("dataset_id", obj.toString());
        editorEdit.putString("endpoint", obj2.toString());
        editorEdit.putString("access_key", obj3.toString());
        editorEdit.apply();
        com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
        com.google.mlkit.common.sdkinternal.model.a.w(y.d, "com.facebook.appevents.cloudbridge.c".toString(), " \n\nSaving Cloudbridge settings from saved Prefs: \n================\n DATASETID: %s\n URL: %s \n ACCESSKEY: %s \n\n ", obj, obj2, obj3);
    }
}
