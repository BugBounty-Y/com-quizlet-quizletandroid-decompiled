package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.view.KeyEvent;
import android.view.View;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.quizlet.generated.enums.O1;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.EnumC5145a;

/* loaded from: classes2.dex */
public final /* synthetic */ class m implements View.OnKeyListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ m(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.view.View.OnKeyListener
    public final boolean onKey(View view, int i, KeyEvent event) {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                if (AbstractC3617f4.a(i, event) == 21) {
                    ((o) obj).b.setChecked(!r5.isChecked());
                }
                return false;
            case 1:
                if (AbstractC3617f4.a(i, event) == 21) {
                    ((t) obj).b.setChecked(!r5.isChecked());
                }
                return false;
            case 2:
                Intrinsics.checkNotNullParameter(event, "event");
                com.quizlet.quizletandroid.ui.setcreation.viewholders.l lVar = (com.quizlet.quizletandroid.ui.setcreation.viewholders.l) obj;
                lVar.getClass();
                if (event.getAction() != 0) {
                    return false;
                }
                boolean z = lVar.c;
                com.quizlet.quizletandroid.ui.setcreation.viewholders.m mVar = lVar.k;
                if (i == 61 && event.isShiftPressed()) {
                    com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = mVar.i;
                    if (z) {
                        fVar.g(mVar.getAdapterPosition() - 1, O1.DEFINITION);
                    } else {
                        mVar.h().requestFocus();
                        fVar.g(mVar.getAdapterPosition(), O1.WORD);
                    }
                } else {
                    if (i != 61) {
                        return false;
                    }
                    com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar2 = mVar.i;
                    if (z) {
                        mVar.f().requestFocus();
                        fVar2.g(mVar.getAdapterPosition(), O1.DEFINITION);
                    } else {
                        fVar2.g(mVar.getAdapterPosition() + 1, O1.WORD);
                    }
                }
                return true;
            default:
                EnumC5145a enumC5145a = AztecText.q1;
                AztecText this$0 = (AztecText) obj;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                Intrinsics.d(event);
                return this$0.j(event);
        }
    }
}
