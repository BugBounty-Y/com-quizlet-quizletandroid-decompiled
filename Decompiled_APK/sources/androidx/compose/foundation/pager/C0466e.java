package androidx.compose.foundation.pager;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import com.google.android.gms.internal.mlkit_vision_barcode.K4;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.foundation.pager.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0466e extends E {
    public static final com.quizlet.data.repository.explanations.myexplanations.a I = K4.b(C0463b.a, C0465d.b);
    public final InterfaceC0773a0 H;

    public C0466e(int i, float f, Function0 function0) {
        super(f, i);
        this.H = C0776c.z(function0);
    }

    @Override // androidx.compose.foundation.pager.E
    public final int l() {
        return ((Number) ((Function0) ((L0) this.H).getValue()).invoke()).intValue();
    }
}
