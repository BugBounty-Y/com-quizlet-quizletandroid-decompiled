package com.quizlet.quizletandroid.ui.setcreation.dialogs;

import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.dialogs.e;
import com.quizlet.uicommon.ui.common.dialogs.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class c extends DialogInterfaceOnCancelListenerC1151t {
    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        e.a aVar = new e.a(getContext());
        aVar.b = false;
        aVar.f(R.string.u13_set_creation_dialog_title);
        aVar.c(R.string.u13_set_creation_dialog_content);
        final int i = 0;
        aVar.e(R.string.show_more, new f(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.dialogs.b
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
                        com.quizlet.quizletandroid.ui.webpages.a aVar2 = com.quizlet.quizletandroid.ui.webpages.a.a;
                        Context contextRequireContext = cVar.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        aVar2.b(contextRequireContext, "https://help.quizlet.com/hc/articles/360029923632#limitations", cVar.getString(R.string.user_settings_terms_of_service));
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
        aVar.d(R.string.got_it, new f(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.dialogs.b
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
                        com.quizlet.quizletandroid.ui.webpages.a aVar2 = com.quizlet.quizletandroid.ui.webpages.a.a;
                        Context contextRequireContext = cVar.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        aVar2.b(contextRequireContext, "https://help.quizlet.com/hc/articles/360029923632#limitations", cVar.getString(R.string.user_settings_terms_of_service));
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
