package com.google.firebase.messaging;

import android.content.Context;
import android.content.SharedPreferences;
import com.google.android.gms.internal.mlkit_vision_common.C4;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class s implements com.google.android.gms.tasks.d, com.quizlet.uicommon.ui.common.dialogs.f {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ Object b;

    public /* synthetic */ s(Context context, boolean z) {
        this.b = context;
        this.a = z;
    }

    public void a(Throwable th) {
        String loggerTag = (String) this.b;
        Intrinsics.checkNotNullParameter(loggerTag, "$loggerTag");
        String localizedMessage = th.getLocalizedMessage();
        if (localizedMessage == null) {
            localizedMessage = "No message provided.";
        }
        if (this.a) {
            com.snowplowanalytics.core.tracker.e.d(loggerTag, localizedMessage, th);
        } else {
            com.snowplowanalytics.core.tracker.e.b(loggerTag, localizedMessage, th);
        }
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.f
    public void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i) {
        eVar.dismiss();
        if (this.a) {
            ((com.quizlet.features.setpage.r) this.b).finish();
        }
    }

    @Override // com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        SharedPreferences.Editor editorEdit = C4.e((Context) this.b).edit();
        editorEdit.putBoolean("proxy_retention", this.a);
        editorEdit.apply();
    }

    public /* synthetic */ s(boolean z, Object obj) {
        this.a = z;
        this.b = obj;
    }
}
