package androidx.compose.foundation.text.input.internal;

import android.graphics.Rect;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import androidx.appcompat.app.L;
import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.selection.i0;
import androidx.compose.ui.platform.Y0;
import androidx.compose.ui.text.K;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3307y6;
import java.lang.ref.WeakReference;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class B {
    public final View a;
    public final u b;
    public C0492h0 e;
    public i0 f;
    public Y0 g;
    public Rect l;
    public final y m;
    public kotlin.jvm.internal.r c = C0495a.c;
    public kotlin.jvm.internal.r d = C0495a.d;
    public androidx.compose.ui.text.input.A h = new androidx.compose.ui.text.input.A(4, K.b, "");
    public androidx.compose.ui.text.input.m i = androidx.compose.ui.text.input.m.g;
    public final ArrayList j = new ArrayList();
    public final Object k = kotlin.l.a(kotlin.m.c, new androidx.compose.animation.core.K(this, 14));

    public B(View view, C0498d c0498d, u uVar) {
        this.a = view;
        this.b = uVar;
        this.m = new y(c0498d, uVar);
    }

    public final D a(EditorInfo editorInfo) {
        int i;
        int i2;
        int i3 = 8;
        androidx.compose.ui.text.input.A a = this.h;
        String str = a.a.a;
        androidx.compose.ui.text.input.m mVar = this.i;
        int i4 = mVar.e;
        boolean z = mVar.a;
        if (i4 == 1) {
            i = z ? 6 : 0;
        } else if (i4 == 0) {
            i = 1;
        } else if (i4 == 2) {
            i = 2;
        } else if (i4 == 6) {
            i = 5;
        } else if (i4 == 5) {
            i = 7;
        } else if (i4 == 3) {
            i = 3;
        } else if (i4 == 4) {
            i = 4;
        } else {
            if (i4 != 7) {
                throw new IllegalStateException("invalid ImeAction");
            }
        }
        editorInfo.imeOptions = i;
        C.a.a(editorInfo, mVar.f);
        int i5 = mVar.d;
        if (i5 == 1) {
            i2 = 1;
        } else if (i5 == 2) {
            editorInfo.imeOptions |= Integer.MIN_VALUE;
            i2 = 1;
        } else if (i5 == 3) {
            i2 = 2;
        } else if (i5 == 4) {
            i2 = 3;
        } else if (i5 == 5) {
            i2 = 17;
        } else if (i5 == 6) {
            i2 = 33;
        } else if (i5 == 7) {
            i2 = 129;
        } else if (i5 == 8) {
            i2 = 18;
        } else {
            if (i5 != 9) {
                throw new IllegalStateException("Invalid Keyboard Type");
            }
            i2 = 8194;
        }
        editorInfo.inputType = i2;
        if (!z && (i2 & 1) == 1) {
            editorInfo.inputType = i2 | 131072;
            if (mVar.e == 1) {
                editorInfo.imeOptions |= 1073741824;
            }
        }
        int i6 = editorInfo.inputType;
        if ((i6 & 1) == 1) {
            int i7 = mVar.b;
            if (i7 == 1) {
                editorInfo.inputType = i6 | 4096;
            } else if (i7 == 2) {
                editorInfo.inputType = i6 | 8192;
            } else if (i7 == 3) {
                editorInfo.inputType = i6 | 16384;
            }
            if (mVar.c) {
                editorInfo.inputType |= 32768;
            }
        }
        int i8 = K.c;
        long j = a.b;
        editorInfo.initialSelStart = (int) (j >> 32);
        editorInfo.initialSelEnd = (int) (j & 4294967295L);
        AbstractC3307y6.b(editorInfo, str);
        editorInfo.imeOptions |= 33554432;
        if (!androidx.compose.foundation.text.handwriting.e.a || i5 == 7 || i5 == 8) {
            AbstractC3307y6.c(editorInfo, false);
        } else {
            AbstractC3307y6.c(editorInfo, true);
            o.a.a(editorInfo);
        }
        z zVar = A.a;
        if (androidx.emoji2.text.j.c()) {
            androidx.emoji2.text.j.a().h(editorInfo);
        }
        D d = new D(this.h, new L(this, i3), this.i.c, this.e, this.f, this.g);
        this.j.add(new WeakReference(d));
        return d;
    }
}
