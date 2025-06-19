package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.q4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3705q4 implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static SharedPreferences d(androidx.fragment.app.I i) {
        return i.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOT_SDK_APP_CONFIGURATION", 0);
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public boolean b() {
        return false;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public Intent[] c(Context context, com.quizlet.quizletandroid.managers.deeplinks.h hVar) {
        return AbstractC3508o4.b(this, context, hVar);
    }
}
