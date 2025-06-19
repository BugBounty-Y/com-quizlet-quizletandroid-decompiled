package org.wordpress.aztec.handlers;

import android.text.Spannable;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.spans.AztecListSpan;
import org.wordpress.aztec.spans.P;
import org.wordpress.aztec.spans.Q;

/* loaded from: classes3.dex */
public final class d extends b {
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(Class cls, int i) {
        super(cls);
        this.h = i;
    }

    @Override // org.wordpress.aztec.handlers.b
    public final void d() {
        a().c();
        Spannable spannable = b();
        int i = this.d;
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        spannable.setSpan(new P(), i, i + 1, 33);
    }

    @Override // org.wordpress.aztec.handlers.b
    public final void e() {
        a().d(this.d);
        Spannable spannable = b();
        int i = this.d;
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        spannable.setSpan(new P(), i, i + 1, 33);
        Spannable text = b();
        int i2 = this.d;
        Intrinsics.checkNotNullParameter(text, "text");
        text.setSpan(new Q(), i2, i2 + 1, 33);
    }

    @Override // org.wordpress.aztec.handlers.b
    public boolean h() {
        switch (this.h) {
            case 0:
                int i = this.e;
                int i2 = i - 1;
                int iA = ((AztecListSpan) a().b).a();
                return i2 <= iA && iA <= i;
            default:
                return super.h();
        }
    }
}
