package com.google.android.gms.internal.ads;

import android.content.DialogInterface;
import android.webkit.JsPromptResult;
import android.widget.EditText;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.im, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class DialogInterfaceOnClickListenerC2194im implements DialogInterface.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ DialogInterfaceOnClickListenerC2194im(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // android.content.DialogInterface.OnClickListener
    public final void onClick(DialogInterface dialogInterface, int i) {
        switch (this.a) {
            case 0:
                BinderC2408nm binderC2408nm = (BinderC2408nm) this.b;
                binderC2408nm.e.a(binderC2408nm.f);
                HashMap map = new HashMap();
                map.put("dialog_action", "dismiss");
                binderC2408nm.i4(binderC2408nm.f, "rtsdc", map);
                com.google.android.gms.ads.internal.overlay.d dVar = (com.google.android.gms.ads.internal.overlay.d) this.c;
                if (dVar != null) {
                    dVar.b();
                    break;
                }
                break;
            case 1:
                BinderC2408nm binderC2408nm2 = (BinderC2408nm) this.b;
                binderC2408nm2.e.a(binderC2408nm2.f);
                HashMap map2 = new HashMap();
                map2.put("dialog_action", "dismiss");
                binderC2408nm2.i4(binderC2408nm2.f, "dialog_click", map2);
                com.google.android.gms.ads.internal.overlay.d dVar2 = (com.google.android.gms.ads.internal.overlay.d) this.c;
                if (dVar2 != null) {
                    dVar2.b();
                    break;
                }
                break;
            default:
                ((JsPromptResult) this.b).confirm(((EditText) this.c).getText().toString());
                break;
        }
    }
}
