package com.quizlet.login.common.util;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.quizlet.assembly.compose.buttons.C4093s;
import com.quizlet.assembly.compose.buttons.C4097w;
import com.quizlet.assembly.compose.buttons.InterfaceC4099y;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.login.common.interactors.data.e;
import com.quizlet.login.common.interactors.data.f;
import com.quizlet.login.common.interactors.data.g;
import com.quizlet.login.common.interactors.data.h;
import com.quizlet.login.common.interactors.data.i;
import com.quizlet.login.common.interactors.data.j;
import com.quizlet.quizletandroid.R;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.I;

/* loaded from: classes3.dex */
public abstract class c {
    public static final long a = TimeUnit.MINUTES.toMillis(5);
    public static final /* synthetic */ int b = 0;

    public static final InterfaceC4099y a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1787982511);
        androidx.compose.material3.windowsizeclass.b bVarG = AbstractC3205m5.g(c0814p);
        Set set = androidx.compose.material3.windowsizeclass.c.b;
        InterfaceC4099y interfaceC4099y = bVarG.a == 0 ? C4093s.a : C4097w.a;
        c0814p.p(false);
        return interfaceC4099y;
    }

    public static final Integer b(j jVar) {
        Intrinsics.checkNotNullParameter(jVar, "<this>");
        if (Intrinsics.b(jVar, h.a)) {
            return Integer.valueOf(R.string.signup_invalid_email);
        }
        if (Intrinsics.b(jVar, e.a)) {
            return Integer.valueOf(R.string.signup_invalid_account_already_exist);
        }
        if (Intrinsics.b(jVar, g.a)) {
            return Integer.valueOf(R.string.signup_email_validation_generic_error);
        }
        if (Intrinsics.b(jVar, f.a) || Intrinsics.b(jVar, i.a)) {
            return null;
        }
        throw new NoWhenBranchMatchedException();
    }

    public static final boolean c(DBUser dBUser) {
        Intrinsics.checkNotNullParameter(dBUser, "<this>");
        return new Date().getTime() - TimeUnit.SECONDS.toMillis((long) dBUser.getTimestamp()) < a;
    }

    public static final String d(String str) {
        String strC = I.C(3, str);
        String strN = D.n(3, "*");
        if (str.length() > 3) {
            return android.support.v4.media.session.a.k(strC, strN);
        }
        Intrinsics.checkNotNullParameter(strC, "<this>");
        int length = strC.length() - 1;
        if (length < 0) {
            length = 0;
        }
        return android.support.v4.media.session.a.k(I.C(length, strC), strN);
    }
}
