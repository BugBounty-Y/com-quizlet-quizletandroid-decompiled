package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

import android.view.View;
import android.widget.TextView;
import androidx.lifecycle.A;
import androidx.lifecycle.H;
import androidx.lifecycle.J;

/* loaded from: classes2.dex */
public final /* synthetic */ class r implements H {
    public final /* synthetic */ int a;
    public final /* synthetic */ s b;

    public /* synthetic */ r(s sVar, int i) {
        this.a = i;
        this.b = sVar;
    }

    @Override // androidx.lifecycle.H
    public final void d(J j, A a) {
        View view;
        switch (this.a) {
            case 0:
                s sVar = this.b;
                sVar.getClass();
                if (a.compareTo(A.ON_RESUME) == 0) {
                    sVar.x.clearFocus();
                    sVar.w.clearFocus();
                    sVar.v.clearFocus();
                    break;
                }
                break;
            case 1:
                s sVar2 = this.b;
                sVar2.getClass();
                if (a.compareTo(A.ON_RESUME) == 0) {
                    sVar2.t.L();
                    break;
                }
                break;
            default:
                s sVar3 = this.b;
                sVar3.getClass();
                if (a.compareTo(A.ON_RESUME) == 0) {
                    b bVar = sVar3.u;
                    TextView textView = bVar.b;
                    if (textView == null || com.onetrust.otpublishers.headless.Internal.a.j(textView.getText().toString())) {
                        view = bVar.e;
                        if (view == null) {
                        }
                    } else {
                        view = bVar.b;
                    }
                    view.requestFocus();
                    break;
                }
                break;
        }
    }
}
