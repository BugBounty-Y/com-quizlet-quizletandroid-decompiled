package com.google.android.gms.internal.ads;

import android.content.DialogInterface;
import android.webkit.JsPromptResult;
import android.webkit.JsResult;

/* renamed from: com.google.android.gms.internal.ads.me, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class DialogInterfaceOnCancelListenerC2357me implements DialogInterface.OnCancelListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ DialogInterfaceOnCancelListenerC2357me(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.content.DialogInterface.OnCancelListener
    public final void onCancel(DialogInterface dialogInterface) {
        switch (this.a) {
            case 0:
                ((JsResult) this.b).cancel();
                break;
            case 1:
                ((JsPromptResult) this.b).cancel();
                break;
            default:
                com.google.android.gms.ads.internal.overlay.d dVar = (com.google.android.gms.ads.internal.overlay.d) this.b;
                if (dVar != null) {
                    dVar.b();
                    break;
                }
                break;
        }
    }
}
