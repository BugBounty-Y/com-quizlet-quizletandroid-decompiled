package com.quizlet.quizletandroid.ui.permissions;

import android.app.Dialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import androidx.fragment.app.I;
import com.quizlet.uicommon.ui.common.dialogs.e;
import com.quizlet.uicommon.ui.common.dialogs.f;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class c extends DialogInterfaceOnCancelListenerC1151t {
    public final u q;
    public final u r;
    public final u s;
    public final u t;

    public c() {
        final int i = 0;
        this.q = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.permissions.b
            public final /* synthetic */ c b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i) {
                    case 0:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_title_resid"));
                    case 1:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_message_resid"));
                    case 2:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_confirm_resid"));
                    default:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_cancel_resid"));
                }
            }
        });
        final int i2 = 1;
        this.r = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.permissions.b
            public final /* synthetic */ c b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i2) {
                    case 0:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_title_resid"));
                    case 1:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_message_resid"));
                    case 2:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_confirm_resid"));
                    default:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_cancel_resid"));
                }
            }
        });
        final int i3 = 2;
        this.s = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.permissions.b
            public final /* synthetic */ c b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i3) {
                    case 0:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_title_resid"));
                    case 1:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_message_resid"));
                    case 2:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_confirm_resid"));
                    default:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_cancel_resid"));
                }
            }
        });
        final int i4 = 3;
        this.t = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.permissions.b
            public final /* synthetic */ c b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                switch (i4) {
                    case 0:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_title_resid"));
                    case 1:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_message_resid"));
                    case 2:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_confirm_resid"));
                    default:
                        return Integer.valueOf(this.b.requireArguments().getInt("arg_cancel_resid"));
                }
            }
        });
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        e.a aVar = new e.a(getContext());
        aVar.b = false;
        aVar.f(((Number) this.q.getValue()).intValue());
        aVar.c(((Number) this.r.getValue()).intValue());
        final int i = 0;
        aVar.e(((Number) this.s.getValue()).intValue(), new f(this) { // from class: com.quizlet.quizletandroid.ui.permissions.a
            public final /* synthetic */ c b;

            {
                this.b = this;
            }

            @Override // com.quizlet.uicommon.ui.common.dialogs.f
            public final void c(e eVar, int i2) {
                switch (i) {
                    case 0:
                        c cVar = this.b;
                        cVar.getClass();
                        Intent intent = new Intent();
                        intent.setAction("android.settings.APPLICATION_DETAILS_SETTINGS");
                        I activity = cVar.getActivity();
                        intent.setData(Uri.fromParts("package", activity != null ? activity.getPackageName() : null, null));
                        cVar.startActivity(intent);
                        Dialog dialog = cVar.l;
                        if (dialog != null) {
                            dialog.dismiss();
                            break;
                        }
                        break;
                    default:
                        Dialog dialog2 = this.b.l;
                        if (dialog2 != null) {
                            dialog2.dismiss();
                            break;
                        }
                        break;
                }
            }
        });
        final int i2 = 1;
        aVar.d(((Number) this.t.getValue()).intValue(), new f(this) { // from class: com.quizlet.quizletandroid.ui.permissions.a
            public final /* synthetic */ c b;

            {
                this.b = this;
            }

            @Override // com.quizlet.uicommon.ui.common.dialogs.f
            public final void c(e eVar, int i22) {
                switch (i2) {
                    case 0:
                        c cVar = this.b;
                        cVar.getClass();
                        Intent intent = new Intent();
                        intent.setAction("android.settings.APPLICATION_DETAILS_SETTINGS");
                        I activity = cVar.getActivity();
                        intent.setData(Uri.fromParts("package", activity != null ? activity.getPackageName() : null, null));
                        cVar.startActivity(intent);
                        Dialog dialog = cVar.l;
                        if (dialog != null) {
                            dialog.dismiss();
                            break;
                        }
                        break;
                    default:
                        Dialog dialog2 = this.b.l;
                        if (dialog2 != null) {
                            dialog2.dismiss();
                            break;
                        }
                        break;
                }
            }
        });
        e eVarB = aVar.b();
        Intrinsics.checkNotNullExpressionValue(eVarB, "create(...)");
        return eVarB;
    }
}
