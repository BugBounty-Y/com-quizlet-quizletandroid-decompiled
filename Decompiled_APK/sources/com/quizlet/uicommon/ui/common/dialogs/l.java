package com.quizlet.uicommon.ui.common.dialogs;

import android.app.Dialog;
import android.os.Bundle;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import com.quizlet.uicommon.ui.common.dialogs.e;

/* loaded from: classes3.dex */
public class l extends DialogInterfaceOnCancelListenerC1151t {
    public static final /* synthetic */ int u = 0;
    public int q;
    public int r;
    public int s;
    public int t;

    public static l P(int i, int i2, int i3) {
        l lVar = new l();
        Bundle bundle = new Bundle();
        bundle.putInt("arg_title_resid", i);
        bundle.putInt("arg_message_resid", i2);
        bundle.putInt("arg_confirm_resid", i3);
        bundle.putInt("arg_cancel_resid", 0);
        lVar.setArguments(bundle);
        return lVar;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        e.a aVar = new e.a(getContext());
        int i = this.q;
        if (i != 0) {
            aVar.f(i);
        }
        int i2 = this.r;
        if (i2 != 0) {
            aVar.c(i2);
        }
        int i3 = this.s;
        if (i3 != 0) {
            aVar.e(i3, new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 25));
        }
        int i4 = this.t;
        if (i4 != 0) {
            aVar.k = aVar.a.getString(i4);
            aVar.l = null;
        }
        return aVar.b();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (getArguments() != null) {
            this.q = getArguments().getInt("arg_title_resid");
            this.r = getArguments().getInt("arg_message_resid");
            this.s = getArguments().getInt("arg_confirm_resid");
            this.t = getArguments().getInt("arg_cancel_resid");
        }
    }
}
