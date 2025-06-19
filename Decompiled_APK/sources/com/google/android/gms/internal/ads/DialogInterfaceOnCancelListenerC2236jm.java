package com.google.android.gms.internal.ads;

import android.content.DialogInterface;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.jm, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class DialogInterfaceOnCancelListenerC2236jm implements DialogInterface.OnCancelListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ BinderC2408nm b;
    public final /* synthetic */ com.google.android.gms.ads.internal.overlay.d c;

    public /* synthetic */ DialogInterfaceOnCancelListenerC2236jm(BinderC2408nm binderC2408nm, com.google.android.gms.ads.internal.overlay.d dVar, int i) {
        this.a = i;
        this.b = binderC2408nm;
        this.c = dVar;
    }

    @Override // android.content.DialogInterface.OnCancelListener
    public final void onCancel(DialogInterface dialogInterface) {
        switch (this.a) {
            case 0:
                BinderC2408nm binderC2408nm = this.b;
                binderC2408nm.e.a(binderC2408nm.f);
                HashMap map = new HashMap();
                map.put("dialog_action", "dismiss");
                binderC2408nm.i4(binderC2408nm.f, "rtsdc", map);
                com.google.android.gms.ads.internal.overlay.d dVar = this.c;
                if (dVar != null) {
                    dVar.b();
                    break;
                }
                break;
            default:
                BinderC2408nm binderC2408nm2 = this.b;
                binderC2408nm2.e.a(binderC2408nm2.f);
                HashMap map2 = new HashMap();
                map2.put("dialog_action", "dismiss");
                binderC2408nm2.i4(binderC2408nm2.f, "dialog_click", map2);
                com.google.android.gms.ads.internal.overlay.d dVar2 = this.c;
                if (dVar2 != null) {
                    dVar2.b();
                    break;
                }
                break;
        }
    }
}
