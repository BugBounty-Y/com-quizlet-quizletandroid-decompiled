package androidx.compose.ui.platform;

import android.view.ActionMode;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class W implements S0 {
    public final C0971v a;
    public ActionMode b;
    public final androidx.camera.camera2.internal.c0 c = new androidx.camera.camera2.internal.c0(new androidx.compose.ui.input.nestedscroll.b(this, 9));
    public int d = 2;

    public W(C0971v c0971v) {
        this.a = c0971v;
    }

    public final void a(androidx.compose.ui.geometry.c cVar, Function0 function0, androidx.compose.foundation.text.I i, androidx.compose.foundation.text.I i2, Function0 function02) {
        androidx.camera.camera2.internal.c0 c0Var = this.c;
        c0Var.c = cVar;
        c0Var.d = function0;
        c0Var.f = i2;
        c0Var.e = i;
        c0Var.g = function02;
        ActionMode actionMode = this.b;
        if (actionMode != null) {
            actionMode.invalidate();
            return;
        }
        this.d = 1;
        this.b = T0.a.b(this.a, new androidx.compose.ui.platform.actionmodecallback.a(c0Var), 1);
    }
}
