package com.google.android.gms.internal.ads;

import android.content.DialogInterface;
import android.webkit.JsPromptResult;
import org.json.JSONException;

/* renamed from: com.google.android.gms.internal.ads.ob, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class DialogInterfaceOnClickListenerC2440ob implements DialogInterface.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ DialogInterfaceOnClickListenerC2440ob(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.content.DialogInterface.OnClickListener
    public final void onClick(DialogInterface dialogInterface, int i) throws JSONException {
        switch (this.a) {
            case 0:
                ((C2483pb) this.b).u("User canceled the download.");
                break;
            default:
                ((JsPromptResult) this.b).cancel();
                break;
        }
    }
}
