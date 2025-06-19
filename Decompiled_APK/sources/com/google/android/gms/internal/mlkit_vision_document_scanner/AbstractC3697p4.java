package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.view.View;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.p4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3697p4 implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final void d(View view, String str) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        if (str == null || str.length() == 0) {
            return;
        }
        view.setBackgroundColor(Color.parseColor(str));
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
