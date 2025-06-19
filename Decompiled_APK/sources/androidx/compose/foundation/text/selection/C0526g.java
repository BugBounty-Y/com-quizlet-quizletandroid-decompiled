package androidx.compose.foundation.text.selection;

import android.graphics.PorterDuffColorFilter;
import android.os.Build;
import androidx.compose.ui.graphics.C0848h;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0854n;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.text.selection.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0526g extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ long a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ boolean c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0526g(long j, Function0 function0, boolean z) {
        super(1);
        this.a = j;
        this.b = function0;
        this.c = z;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.draw.d dVar = (androidx.compose.ui.draw.d) obj;
        C0848h c0848hQ = W.q(dVar, androidx.compose.ui.geometry.e.d(dVar.a.g()) / 2.0f);
        int i = Build.VERSION.SDK_INT;
        long j = this.a;
        return dVar.b(new androidx.compose.foundation.lazy.p(1, this.b, c0848hQ, new C0853m(j, 5, i >= 29 ? C0854n.a.a(j, 5) : new PorterDuffColorFilter(androidx.compose.ui.graphics.F.A(j), androidx.compose.ui.graphics.F.E(5))), this.c));
    }
}
