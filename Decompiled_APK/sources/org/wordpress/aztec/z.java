package org.wordpress.aztec;

import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.widget.EditText;
import com.google.android.gms.internal.mlkit_vision_camera.J2;
import java.util.LinkedList;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.source.SourceViewEditText;

/* loaded from: classes3.dex */
public final class z {
    public final boolean a;
    public final int b;
    public int c;
    public final androidx.core.provider.k g;
    public boolean h;
    public LinkedList d = new LinkedList();
    public String e = "";
    public final Handler f = new Handler(Looper.getMainLooper());
    public final long i = 500;

    public z(boolean z, int i) {
        this.a = z;
        this.b = i;
        if (z) {
            this.g = new androidx.core.provider.k(this);
        } else {
            this.g = null;
        }
    }

    public final void a(EditText editText) {
        String strValueOf;
        Intrinsics.checkNotNullParameter(editText, "editText");
        androidx.core.provider.k kVar = this.g;
        if (kVar == null || !this.a) {
            return;
        }
        Handler handler = this.f;
        handler.removeCallbacks(kVar);
        if (!this.h) {
            this.h = true;
            if (editText instanceof AztecText) {
                AztecText aztecText = (AztecText) editText;
                Editable content = aztecText.getText();
                Intrinsics.checkNotNullParameter(content, "content");
                Intrinsics.checkNotNullParameter(content, "content");
                String strQ = aztecText.q(content);
                if (aztecText.y) {
                    strQ = J2.b(strQ, true);
                }
                strValueOf = J2.b(strQ, aztecText.y);
            } else {
                strValueOf = editText instanceof SourceViewEditText ? String.valueOf(((SourceViewEditText) editText).getText()) : "";
            }
            Intrinsics.checkNotNullParameter(strValueOf, "<set-?>");
            kVar.c = strValueOf;
            kVar.d = editText;
        }
        handler.postDelayed(kVar, this.i);
    }
}
