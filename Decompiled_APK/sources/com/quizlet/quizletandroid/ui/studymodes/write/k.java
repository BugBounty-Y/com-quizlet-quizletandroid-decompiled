package com.quizlet.quizletandroid.ui.studymodes.write;

import android.view.View;
import com.quizlet.db.data.models.persisted.base.Models;

/* loaded from: classes3.dex */
public final class k implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ WriteModeResultsView b;

    public /* synthetic */ k(WriteModeResultsView writeModeResultsView, int i) {
        this.a = i;
        this.b = writeModeResultsView;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        switch (this.a) {
            case 0:
                Object obj = this.b.g;
                boolean z = ((com.quizlet.features.write.base.b) obj).r;
                WriteModeActivity writeModeActivity = (WriteModeActivity) obj;
                if (writeModeActivity.u.B.i() == 0) {
                    z = false;
                }
                writeModeActivity.Q(z);
                writeModeActivity.O();
                writeModeActivity.j1.c(Models.SESSION);
                writeModeActivity.a0();
                break;
            default:
                Object obj2 = this.b.g;
                boolean z2 = !((com.quizlet.features.write.base.b) obj2).r;
                WriteModeActivity writeModeActivity2 = (WriteModeActivity) obj2;
                if (writeModeActivity2.u.B.i() == 0) {
                    z2 = false;
                }
                writeModeActivity2.Q(z2);
                writeModeActivity2.O();
                writeModeActivity2.j1.c(Models.SESSION);
                writeModeActivity2.a0();
                break;
        }
    }
}
