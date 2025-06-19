package com.quizlet.features.emailconfirmation.ui.activities;

import android.os.Bundle;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.p0;
import androidx.navigation.compose.C1278k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes2.dex */
public final class MagicLinkConfirmationActivity extends l {
    public static final String r;
    public com.quizlet.quizletandroid.ui.navigationmanagers.a p;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e q;

    static {
        Intrinsics.checkNotNullExpressionValue("MagicLinkConfirmationActivity", "getSimpleName(...)");
        r = "MagicLinkConfirmationActivity";
    }

    public MagicLinkConfirmationActivity() {
        super(1);
        this.q = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.emailconfirmation.viewmodel.m.class), new q(this, 1), new q(this, 0), new q(this, 2));
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return r;
    }

    public final void P(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1859077323);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC3178j5.b(null, false, null, androidx.compose.runtime.internal.e.e(-371278699, new m(this, 0), c0814p), c0814p, 3072, 7);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(this, i, 8);
        }
    }

    @Override // com.quizlet.features.emailconfirmation.ui.activities.l, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        E.A(p0.h(this), null, null, new p(this, null), 3);
        androidx.activity.compose.j.a(this, new androidx.compose.runtime.internal.d(true, -221586242, new m(this, 1)));
    }

    @Override // com.quizlet.baseui.base.b
    public final int z() {
        return 0;
    }
}
