package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.facebook.AccessToken;
import com.facebook.FacebookException;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.M5;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class D {
    public static final void a(com.quizlet.features.setpage.termlist.data.m selectedOption, com.quizlet.assembly.compose.menu.s state, Function0 onSortButtonClick, Function1 onSortMenuOptionItemClick, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        int i2;
        Intrinsics.checkNotNullParameter(selectedOption, "selectedSortOption");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(onSortButtonClick, "onSortButtonClick");
        Intrinsics.checkNotNullParameter(onSortMenuOptionItemClick, "onSortMenuOptionItemClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-207279310);
        int i3 = i | (c0814p.f(selectedOption) ? 4 : 2) | (c0814p.h(state) ? 32 : 16) | (c0814p.h(onSortButtonClick) ? 256 : 128) | (c0814p.h(onSortMenuOptionItemClick) ? 2048 : 1024) | 24576;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            qVar2 = qVar;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            Intrinsics.checkNotNullParameter(selectedOption, "selectedOption");
            c0814p.X(-1745100);
            List listB = kotlin.collections.A.b(new com.quizlet.assembly.compose.menu.n(AbstractC3106b5.d(c0814p, R.string.term_list_sort_menu_title)));
            kotlin.enums.b bVar = com.quizlet.features.setpage.termlist.data.m.c;
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(bVar, 10));
            Iterator it2 = bVar.iterator();
            while (it2.hasNext()) {
                com.quizlet.features.setpage.termlist.data.m mVar = (com.quizlet.features.setpage.termlist.data.m) it2.next();
                boolean z = mVar == selectedOption;
                c0814p.X(1267764992);
                int iOrdinal = mVar.ordinal();
                if (iOrdinal == 0) {
                    i2 = R.string.term_list_term_sort_menu_option_original;
                } else {
                    if (iOrdinal != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    i2 = R.string.term_list_term_sort_menu_option_alphabetical;
                }
                c0814p.p(false);
                arrayList.add(new com.quizlet.assembly.compose.menu.o(mVar, AbstractC3106b5.d(c0814p, i2), null, null, false, z ? com.quizlet.assembly.compose.menu.p.a : com.quizlet.assembly.compose.menu.p.d, false, 188));
            }
            ArrayList arrayListC0 = CollectionsKt.c0(listB, arrayList);
            c0814p.p(false);
            state.c(arrayListC0, true);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
            int i4 = c0814p.P;
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
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p, R.string.term_list_header), null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).j, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            AbstractC0382e.f(c0814p, new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true));
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(349760719, new com.quizlet.features.practicetest.results.i(8, selectedOption, onSortButtonClick), c0814p);
            c0814p.X(1655271317);
            boolean zH = c0814p.h(state);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.features.setpage.termlist.ui.d(state, 0);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            M5.a(dVarE, null, state, onSortMenuOptionItemClick, null, (Function0) objI, c0814p, ((i3 << 3) & 896) | 6 | (i3 & 7168), 18);
            c0814p.p(true);
            qVar2 = nVar;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r(selectedOption, state, onSortButtonClick, onSortMenuOptionItemClick, qVar2, i);
        }
    }

    public static AccessToken b(JSONObject jsonObject) {
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        if (jsonObject.getInt("version") > 1) {
            throw new FacebookException("Unknown AccessToken serialization format.");
        }
        String token = jsonObject.getString("token");
        Date date = new Date(jsonObject.getLong("expires_at"));
        JSONArray permissionsArray = jsonObject.getJSONArray("permissions");
        JSONArray declinedPermissionsArray = jsonObject.getJSONArray("declined_permissions");
        JSONArray jSONArrayOptJSONArray = jsonObject.optJSONArray("expired_permissions");
        Date date2 = new Date(jsonObject.getLong("last_refresh"));
        String string = jsonObject.getString("source");
        Intrinsics.checkNotNullExpressionValue(string, "jsonObject.getString(SOURCE_KEY)");
        com.facebook.g gVarValueOf = com.facebook.g.valueOf(string);
        String applicationId = jsonObject.getString("application_id");
        String userId = jsonObject.getString("user_id");
        Date date3 = new Date(jsonObject.optLong("data_access_expiration_time", 0L));
        String strOptString = jsonObject.optString("graph_domain", null);
        Intrinsics.checkNotNullExpressionValue(token, "token");
        Intrinsics.checkNotNullExpressionValue(applicationId, "applicationId");
        Intrinsics.checkNotNullExpressionValue(userId, "userId");
        Intrinsics.checkNotNullExpressionValue(permissionsArray, "permissionsArray");
        ArrayList arrayListF = com.facebook.internal.J.F(permissionsArray);
        Intrinsics.checkNotNullExpressionValue(declinedPermissionsArray, "declinedPermissionsArray");
        return new AccessToken(token, applicationId, userId, arrayListF, com.facebook.internal.J.F(declinedPermissionsArray), jSONArrayOptJSONArray == null ? new ArrayList() : com.facebook.internal.J.F(jSONArrayOptJSONArray), gVarValueOf, date, date2, date3, strOptString);
    }

    public static AccessToken c() {
        return com.facebook.f.f.o().c;
    }

    public static boolean d() {
        AccessToken accessToken = com.facebook.f.f.o().c;
        return (accessToken == null || new Date().after(accessToken.a)) ? false : true;
    }
}
