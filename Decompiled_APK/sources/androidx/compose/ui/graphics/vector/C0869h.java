package androidx.compose.ui.graphics.vector;

import android.graphics.PathMeasure;
import androidx.compose.ui.graphics.C0851k;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.ui.graphics.vector.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0869h extends kotlin.jvm.internal.r implements Function0 {
    public static final C0869h b = new C0869h(0, 0);
    public static final C0869h c = new C0869h(0, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0869h(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return new C0851k(new PathMeasure());
            default:
                return Unit.a;
        }
    }
}
